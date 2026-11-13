package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

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
		return humanBytes(n)
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
	return truncateWidth(strings.Join(strings.Fields(cellStr(v)), " "), w)
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
	tab := layoutTable([]string{"", ""}, rows)
	return tab[strings.Index(tab, "\n")+1:]
}

type activityData struct {
	Conn     string           `json:"conn"`
	Count    int              `json:"count"`
	Sessions []map[string]any `json:"sessions"`
}

func (d activityData) Text() string {
	if len(d.Sessions) == 0 {
		return noneYet("busy sessions", "", "idle ones show with --all")
	}
	var rows [][]string
	for _, s := range d.Sessions {
		state := cellStr(s["state"])
		if state == "" {
			state = cellStr(s["command"])
		}
		rows = append(rows, []string{cellStr(s["pid"]), cellStr(s["user"]), cellStr(s["database"]), secsText(s["running_seconds"]), state, oneLine(s["query"], 60)})
	}
	return dataTable([]string{"pid", "user", "db", "time", "state", "query"}, rows)
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
	return dataTable([]string{"waiting", "for", "waiting query", "blocking", "blocking query"}, rows) +
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
		sb.WriteString(dataTable([]string{"database", "size"}, rows))
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
		sb.WriteString("\n" + dataTable([]string{"table", "rows", "total", "index"}, rows))
	}
	if ix := list("indexes"); len(ix) > 0 {
		var rows [][]string
		for _, r := range ix {
			rows = append(rows, []string{cellStr(r["name"]), cellStr(r["table"]), sizeText(r["bytes"]), cellStr(r["scans"])})
		}
		sb.WriteString("\n" + dataTable([]string{"index", "table", "size", "scans"}, rows))
	}
	return sb.String()
}

// sortedKeys lists a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
