package cli

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/dbx"
)

// Text views of the db commands. JSON keeps raw numbers (bytes, seconds);
// text shows them the way people read them (7.5 MiB, 3h).

// writeDelimited prints every row set as CSV, or TSV with tsv (\t, \n and
// \ escaped like PostgreSQL's text format). NULL is an empty field.
func writeDelimited(w io.Writer, res *dbx.Result, tsv bool) error {
	cw := csv.NewWriter(w)
	tsvField := strings.NewReplacer(`\`, `\\`, "\t", `\t`, "\n", `\n`, "\r", `\r`)
	first := true
	for _, r := range res.Results {
		if r.Columns == nil {
			continue
		}
		if !first {
			fmt.Fprintln(w)
		}
		first = false
		write := func(fields []string) error {
			if !tsv {
				return cw.Write(fields)
			}
			for i := range fields {
				fields[i] = tsvField.Replace(fields[i])
			}
			_, err := fmt.Fprintln(w, strings.Join(fields, "\t"))
			return err
		}
		head := make([]string, len(r.Columns))
		for i, c := range r.Columns {
			head[i] = c.Name
		}
		if err := write(head); err != nil {
			return err
		}
		for _, row := range r.Rows {
			fields := make([]string, len(row))
			for i, v := range row {
				switch v.(type) {
				case nil:
				case map[string]string:
					fields[i] = cellText(v, true)
				default:
					fields[i] = fmt.Sprint(v)
				}
			}
			if err := write(fields); err != nil {
				return err
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
	}
	return nil
}

// dataNum reads an integer the database returned (int64, float, or text).
func dataNum(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case int:
		return int64(x), true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	case []byte:
		n, err := strconv.ParseInt(string(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func cellStr(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func sizeText(v any) string {
	if n, ok := dataNum(v); ok {
		return term.HumanBytes(n)
	}
	return cellStr(v)
}

func secsText(v any) string {
	if n, ok := dataNum(v); ok {
		return humanAge(time.Duration(n) * time.Second)
	}
	return cellStr(v)
}

// oneLine shows a query on one table line.
func oneLine(v any, w int) string {
	return term.TruncateWidth(strings.Join(strings.Fields(cellStr(v)), " "), w)
}

// dbInfoData marshals like the map it wraps, so JSON stays as it was.
type dbInfoData map[string]any

func (d dbInfoData) Text() string {
	var rows [][]string
	add := func(label, value string) {
		if value != "" {
			rows = append(rows, []string{label + ":", value})
		}
	}
	add("conn", cellStr(d["conn"]))
	add("kind", cellStr(d["kind"]))
	add("version", cellStr(d["version"]))
	add("project", cellStr(d["project"])) // BigQuery
	add("dataset", cellStr(d["dataset"]))
	add("location", cellStr(d["location"]))
	add("database", cellStr(d["database"]))
	add("user", cellStr(d["user"]))
	add("role", cellStr(d["role"]))
	if d["replay_lag_seconds"] != nil {
		add("replay lag", secsText(d["replay_lag_seconds"]))
	}
	if d["uptime_seconds"] != nil {
		add("uptime", secsText(d["uptime_seconds"]))
	}
	if d["size_bytes"] != nil {
		add("size", sizeText(d["size_bytes"]))
	}
	if d["connections"] != nil {
		c := cellStr(d["connections"])
		if d["max_connections"] != nil {
			c += " of " + cellStr(d["max_connections"])
		}
		add("connections", c)
	}
	add("journal mode", cellStr(d["journal_mode"]))
	tab := term.LayoutTable([]string{"", ""}, rows)
	return tab[strings.Index(tab, "\n")+1:]
}

type activityData struct {
	Conn     string           `json:"conn"`
	Count    int              `json:"count"`
	Sessions []map[string]any `json:"sessions"`
}

func (d activityData) Text() string {
	if len(d.Sessions) == 0 {
		return term.NoneYet("busy sessions", "", "idle ones show with --all")
	}
	var rows [][]string
	for _, s := range d.Sessions {
		state := cellStr(s["state"])
		if state == "" {
			state = cellStr(s["command"])
		}
		rows = append(rows, []string{cellStr(s["pid"]), cellStr(s["user"]), cellStr(s["database"]), secsText(s["running_seconds"]), state, oneLine(s["query"], 60)})
	}
	return term.DataTable([]string{"pid", "user", "db", "time", "state", "query"}, rows)
}

type locksData struct {
	Conn  string           `json:"conn"`
	Count int              `json:"count"`
	Waits []map[string]any `json:"waits"`
}

func (d locksData) Text() string {
	if len(d.Waits) == 0 {
		return "no session is waiting for a lock\n"
	}
	var rows [][]string
	for _, w := range d.Waits {
		rows = append(rows, []string{cellStr(w["waiting_pid"]), secsText(w["waiting_seconds"]), oneLine(w["waiting_query"], 40),
			cellStr(w["blocking_pid"]), oneLine(w["blocking_query"], 40)})
	}
	return term.DataTable([]string{"waiting", "for", "waiting query", "blocking", "blocking query"}, rows) +
		"(stop the blocking query with `komando db kill CONN PID`)\n"
}

type sizesData map[string]any

func (d sizesData) Text() string {
	var sb strings.Builder
	list := func(key string) []map[string]any {
		var res []map[string]any
		b, _ := json.Marshal(d[key])
		_ = json.Unmarshal(b, &res)
		return res
	}
	if dbs := list("databases"); len(dbs) > 0 {
		var rows [][]string
		for _, r := range dbs {
			rows = append(rows, []string{cellStr(r["name"]), sizeText(r["bytes"])})
		}
		sb.WriteString(term.DataTable([]string{"database", "size"}, rows))
	}
	if ts := list("tables"); len(ts) > 0 {
		var rows [][]string
		for _, r := range ts {
			name := cellStr(r["name"])
			if s := cellStr(r["schema"]); s != "" && s != "public" && d["kind"] != "mysql" {
				name = s + "." + name
			}
			rows = append(rows, []string{name, cellStr(r["rows"]), sizeText(r["total_bytes"]), sizeText(r["index_bytes"])})
		}
		sb.WriteString("\n" + term.DataTable([]string{"table", "rows", "total", "index"}, rows))
	}
	if ix := list("indexes"); len(ix) > 0 {
		var rows [][]string
		for _, r := range ix {
			rows = append(rows, []string{cellStr(r["name"]), cellStr(r["table"]), sizeText(r["bytes"]), cellStr(r["scans"])})
		}
		sb.WriteString("\n" + term.DataTable([]string{"index", "table", "size", "scans"}, rows))
	}
	return sb.String()
}

func (d schemaData) Text() string {
	if len(d.Tables) == 0 {
		return term.NoneYet("tables", "", "the database is empty, or the conn's user cannot see them")
	}
	var sb strings.Builder
	detailed := false
	for _, t := range d.Tables {
		if len(t.Columns) > 0 {
			detailed = true
		}
	}
	if !detailed {
		var rows [][]string
		for _, t := range d.Tables {
			n := ""
			if t.RowEstimate != nil {
				n = fmt.Sprint(*t.RowEstimate)
			}
			rows = append(rows, []string{qualified(t), t.Type, n})
		}
		return term.DataTable([]string{"table", "type", "rows (est.)"}, rows)
	}
	for i, t := range d.Tables {
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%s (%s)\n", qualified(t), t.Type)
		var rows [][]string
		for _, c := range t.Columns {
			var notes []string
			if c.PrimaryKey {
				notes = append(notes, "primary key")
			}
			switch c.Identity {
			case "":
			case "auto_increment", "identity":
				notes = append(notes, c.Identity)
			default:
				notes = append(notes, "generated "+c.Identity+" as identity")
			}
			if !c.Nullable {
				notes = append(notes, "not null")
			}
			if c.Default != nil {
				notes = append(notes, "default "+*c.Default)
			}
			rows = append(rows, []string{"  " + c.Name, c.Type, strings.Join(notes, ", ")})
		}
		tab := term.LayoutTable([]string{"", "", ""}, rows)
		sb.WriteString(tab[strings.Index(tab, "\n")+1:]) // no header line
		for _, ix := range t.Indexes {
			fmt.Fprintf(&sb, "  index %s\n", dash(ix.Definition))
		}
		for _, c := range t.Constraints {
			fmt.Fprintf(&sb, "  %s %s: %s\n", c.Type, c.Name, c.Definition)
		}
	}
	return sb.String()
}

func qualified(t dbx.Table) string {
	if t.Schema == "" || t.Schema == "public" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

func (d queryData) Text() string {
	var sb strings.Builder
	for i, r := range d.Results {
		if len(d.Results) > 1 {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "-- %s\n", r.SQL)
		}
		switch {
		case r.Skipped != "":
			fmt.Fprintf(&sb, "(%s)\n", r.Skipped)
		case r.Columns != nil:
			wide := len(r.Columns) == 1 // a single column (EXPLAIN plans, lists) is shown in full
			names := make([]string, len(r.Columns))
			for j, c := range r.Columns {
				names[j] = c.Name
			}
			rows := make([][]string, len(r.Rows))
			for k, row := range r.Rows {
				rows[k] = make([]string, len(row))
				for j, v := range row {
					rows[k][j] = cellText(v, wide)
				}
			}
			sb.WriteString(term.LayoutTable(names, rows))
			note := ""
			switch r.Truncated {
			case "rows":
				note = ", stopped at the --limit row cap: add LIMIT/WHERE, or raise --limit (0 = none)"
			case "bytes":
				note = ", stopped at the output size cap: select fewer columns or rows, or raise --max-output"
			}
			fmt.Fprintf(&sb, "(%d row%s%s)\n", r.RowCount, term.Plural(r.RowCount), note)
		case r.RowsAffected != nil:
			fmt.Fprintf(&sb, "%d row%s affected\n", *r.RowsAffected, term.Plural(int(*r.RowsAffected)))
		default:
			sb.WriteString("ok\n")
		}
		if r.BytesProcessed != nil && r.Skipped == "" {
			fmt.Fprintf(&sb, "(BigQuery read %s)\n", term.HumanBytes(*r.BytesProcessed))
		}
	}
	if d.RolledBack {
		sb.WriteString("dry run: rolled back, nothing changed\n")
	}
	return sb.String()
}

// cellText shows one value in a table: NULL, text with tabs and newlines
// escaped, binary as \x hex (like psql).
func cellText(v any, wide bool) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case string:
		x = strings.NewReplacer("\t", `\t`, "\n", `\n`, "\r", `\r`).Replace(x)
		if !wide {
			x = term.TruncateWidth(x, 80)
		}
		return x
	case map[string]string:
		b, err := base64.StdEncoding.DecodeString(x["base64"])
		if err != nil {
			return "<binary>"
		}
		h := `\x` + hex.EncodeToString(b)
		if !wide {
			h = term.TruncateWidth(h, 80)
		}
		return h
	}
	return fmt.Sprint(v)
}
