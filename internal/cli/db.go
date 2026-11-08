package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Database commands. Safety, in order:
//  1. the SQL is classified before anything is sent (driver.ClassifySQL);
//  2. without --write it runs in a read-only transaction, so the database
//     itself refuses changes the classifier missed;
//  3. --write on a protected conn needs --yes, destructive SQL needs
//     --allow-dangerous (guardConns);
//  4. --dry-run runs the SQL and rolls it back.

const dbDefaultTimeout = 30 * time.Second

func dbCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "db",
		Aliases: []string{"sql"},
		Short:   "Query databases safely: read-only by default, structured results",
		Long: `Run SQL on a conn (see ` + "`komando conn`" + `). Without --write every query runs in a
read-only transaction, so nothing can change. With --write, try --dry-run
first: it runs the SQL and rolls it back, showing how many rows would change.`,
	}
	c.AddCommand(dbQueryCmd(), dbSchemaCmd(), dbExplainCmd(), dbInfoCmd(), dbActivityCmd(), dbLocksCmd(), dbSizesCmd(), dbKillCmd(), dbUserCmd(), dbGrantCmd(false), dbGrantCmd(true), dbGrantsCmd(), dbShellCmd(), dbDumpCmd(), dbRestoreCmd())
	return c
}

type dbFlags struct {
	write bool
	limit int
	args  []string
	csv   bool
	tsv   bool
	// mariaAnalyze: the SQL starts with EXPLAIN ANALYZE, which MariaDB
	// spells ANALYZE
	mariaAnalyze bool
}

func dbQueryCmd() *cobra.Command {
	var f dbFlags
	var file string
	c := &cobra.Command{
		Use:   "query CONN [SQL]",
		Short: "Run SQL; read-only unless --write",
		Long: `Run SQL on a database conn. Without --write it runs in a read-only
transaction. Each run stops after 30s unless --timeout (or the conn's
statement_timeout option) allows more. Placeholders take their values from
--arg, in order. --csv and --tsv print the rows for spreadsheets and scripts.
SQL that starts with a -- comment: pass it after -- or with -f -.`,
		Example: `  komando db query prod-db "select id, email from users order by id desc limit 10"
  komando db query prod-db "select * from users where email = $1" --arg bob@example.com
  komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
  komando db query prod-db --file migration.sql --write --dry-run
  komando db query prod-db --csv "select * from orders" > orders.csv`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var q string
			switch {
			case len(args) == 2 && file == "":
				q = args[1]
			case len(args) == 1 && file != "":
				b, err := readFileOrStdin(file)
				if err != nil {
					return localFileErr("FILE_NOT_FOUND", err, "")
				}
				q = string(b)
			default:
				return out.Usage("give the SQL as an argument or with --file (not both)")
			}
			if f.csv && f.tsv {
				return out.Usage("pick one of --csv and --tsv")
			}
			return runSQL(cmd.Context(), "db.query", args[0], q, f)
		},
	}
	f.bind(c)
	c.Flags().StringVarP(&file, "file", "f", "", "read SQL from a file ('-' for stdin)")
	c.Flags().BoolVar(&f.csv, "csv", false, "print the rows as CSV (header first) instead of JSON or a table")
	c.Flags().BoolVar(&f.tsv, "tsv", false, "print the rows as tab-separated values (header first)")
	c.SetFlagErrorFunc(sqlFlagError)
	return c
}

// sqlFlagError explains the usual cause of an unknown flag here: SQL that
// starts with a -- comment, which reads as a flag.
func sqlFlagError(cmd *cobra.Command, err error) error {
	if rest, ok := strings.CutPrefix(err.Error(), "unknown flag: --"); ok && (rest == "" || strings.ContainsAny(rest, " \t\n")) {
		return out.Errf(out.ExitUsage, "USAGE", "put -- before the SQL (komando db query CONN -- \"-- note ...\"), or read it with -f FILE or -f - (stdin)",
			"the SQL starts with a -- comment, which reads as a flag")
	}
	return err
}

func (f *dbFlags) bind(c *cobra.Command) {
	c.Flags().BoolVar(&f.write, "write", false, "allow changes (runs in a normal transaction; combine with --dry-run to roll back)")
	c.Flags().IntVarP(&f.limit, "limit", "n", 500, "max rows returned per statement (0 = no limit; output size is capped by --max-output too)")
	c.Flags().StringArrayVar(&f.args, "arg", nil, "value for a placeholder ($1 in postgres, ? in mysql/sqlite); repeat in order")
}

func dbExplainCmd() *cobra.Command {
	var f dbFlags
	var analyze bool
	c := &cobra.Command{
		Use:   "explain CONN SQL",
		Short: "Show how the database would run a query (--analyze runs it and measures)",
		Example: `  komando db explain prod-db "select * from orders where user_id = 42"
  komando db explain prod-db --analyze "select count(*) from orders"`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			c, err := singleConn(st, args[0], "db")
			if err != nil {
				return err
			}
			var prefix string
			switch c.Kind {
			case "postgres":
				prefix = "EXPLAIN "
				if analyze {
					prefix = "EXPLAIN (ANALYZE, BUFFERS) "
				}
			case "mysql":
				prefix = "EXPLAIN "
				if analyze {
					prefix = "EXPLAIN ANALYZE " // checked as such; MariaDB gets ANALYZE (runSQL)
					f.mariaAnalyze = true
				}
			case "sqlite":
				if analyze {
					return out.Usage("sqlite has no EXPLAIN ANALYZE; drop --analyze")
				}
				prefix = "EXPLAIN QUERY PLAN "
			default:
				return out.Usage("%s conns do not take SQL", c.Kind)
			}
			return runSQL(cmd.Context(), "db.explain", args[0], prefix+strings.TrimSpace(args[1]), f)
		},
	}
	f.bind(c)
	c.SetFlagErrorFunc(sqlFlagError)
	c.Flags().BoolVar(&analyze, "analyze", false, "run the query and report real timings (a changing query then needs --write)")
	return c
}

func dbSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema CONN [TABLE...]",
		Short: "List tables, or show columns and indexes of the named tables",
		Example: `  komando db schema prod-db
  komando db schema prod-db users public.orders`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			c, err := singleConn(st, args[0], "db")
			if err != nil {
				return err
			}
			db, closeDB, err := openDB(cmd.Context(), st, c, true)
			if err != nil {
				return err
			}
			defer closeDB()
			tables, err := dbx.Schema(cmd.Context(), db, c.Kind, args[1:], connTimeout(c))
			audit(st, "db.schema", nil, "", err == nil, map[string]any{"conns": []string{c.Name}})
			if err != nil {
				return err
			}
			out.P.Print("db.schema", schemaData{Conn: c.Name, Tables: tables}, nil)
			return nil
		},
	}
}

type schemaData struct {
	Conn   string      `json:"conn"`
	Tables []dbx.Table `json:"tables"`
}

func (d schemaData) Text() string {
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
		return dataTable([]string{"table", "type", "rows (est.)"}, rows)
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
			case "auto_increment":
				notes = append(notes, "auto_increment")
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
		tab := layoutTable([]string{"", "", ""}, rows)
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

// singleConn resolves a selector that must match exactly one conn of the
// given family (db, cache, storage).
func dbTimeout() time.Duration {
	if g.timeout > 0 {
		return g.timeout
	}
	return dbDefaultTimeout
}

// connTimeout is dbTimeout with the conn's own statement_timeout option
// (`conn edit NAME --option statement_timeout=10s`); --timeout still wins.
func connTimeout(c *store.Conn) time.Duration {
	if g.timeout > 0 {
		return g.timeout
	}
	if v := c.Options["statement_timeout"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 { // Postgres style: milliseconds
			return time.Duration(ms) * time.Millisecond
		}
	}
	return dbDefaultTimeout
}

// openDB connects to c, through its --via host when set. The returned
// function closes the database and the SSH connection.
func openDB(ctx context.Context, st *store.State, c *store.Conn, readOnly bool) (*sql.DB, func(), error) {
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, sshOpts(st).ConnectTimeout)
	defer cancel()
	db, err := dbx.Open(cctx, c.URL, a.Target, a.Password, a.Dial, readOnly, "komando/"+actor())
	if err != nil {
		a.Close()
		return nil, nil, viaTimeout(c, err)
	}
	return db, func() { db.Close(); a.Close() }, nil
}

type queryData struct {
	Conn   string `json:"conn"`
	Risk   string `json:"risk"`
	Write  bool   `json:"write"`
	DryRun bool   `json:"dry_run,omitempty"`
	*dbx.Result
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
			sb.WriteString(layoutTable(names, rows))
			note := ""
			switch r.Truncated {
			case "rows":
				note = ", stopped at the --limit row cap: add LIMIT/WHERE, or raise --limit (0 = none)"
			case "bytes":
				note = ", stopped at the output size cap: select fewer columns or rows, or raise --max-output"
			}
			fmt.Fprintf(&sb, "(%d row%s%s)\n", r.RowCount, plural(r.RowCount), note)
		case r.RowsAffected != nil:
			fmt.Fprintf(&sb, "%d row%s affected\n", *r.RowsAffected, plural(int(*r.RowsAffected)))
		default:
			sb.WriteString("ok\n")
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
			x = truncateWidth(x, 80)
		}
		return x
	case map[string]string:
		b, err := base64.StdEncoding.DecodeString(x["base64"])
		if err != nil {
			return "<binary>"
		}
		h := `\x` + hex.EncodeToString(b)
		if !wide {
			h = truncateWidth(h, 80)
		}
		return h
	}
	return fmt.Sprint(v)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// runSQL classifies, guards, runs and audits one SQL text on one conn.
func runSQL(ctx context.Context, name, connExpr, query string, f dbFlags) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "db")
	if err != nil {
		return err
	}
	plan, err := driver.ClassifySQL(c.Kind, query)
	if err != nil {
		return err
	}
	rec := map[string]any{"conns": []string{c.Name}, "risk": plan.Risk.String(), "write": f.write}
	switch st.Settings.AuditSQL {
	case "hash":
		sum := sha256.Sum256([]byte(query))
		rec["sql_sha256"] = hex.EncodeToString(sum[:])
	case "off":
	default:
		rec["sql"] = redactSQL(query)
	}
	if len(f.args) > 0 {
		rec["args"] = len(f.args) // values may be personal data; record only how many
	}
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if err := refuseHiddenSQL(f.write, query, f.args); err != nil {
		return fail(err)
	}
	if !f.write && plan.NeedsWrite() {
		e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG",
			"this SQL changes data; re-run with --write (try --write --dry-run first)",
			"%s statement needs --write", plan.Risk)
		if len(plan.RuleIDs) > 0 {
			// say what the matched rule found, not a generic "changes data"
			e.Message += fmt.Sprintf(" (and --allow-dangerous: %s)", strings.Join(plan.Reasons, "; "))
			e.Hint = "this SQL " + strings.Join(plan.Reasons, "; ") + ": only if that is intended, confirm with the user and re-run with --write --allow-dangerous"
		}
		return fail(e)
	}
	if f.write {
		// --write opens a read-write transaction whatever the SQL looks like,
		// so a protected conn asks even for SQL rated read (as db shell does)
		v := plan.Verdict
		v.Risk = max(v.Risk, driver.RiskWrite)
		if err := guardConns(st, []*store.Conn{c}, v); err != nil {
			return fail(err)
		}
		if g.dryRun && out.P.Blocked() != nil {
			// the real run would stop here: run nothing, since the
			// rollback of a dry run does not undo every statement (a
			// killed session, COPY ... PROGRAM, code inside DO)
			res := &dbx.Result{Results: []dbx.StatementResult{}}
			for _, s := range plan.Statements {
				res.Results = append(res.Results, dbx.StatementResult{SQL: s.SQL, Keyword: s.Keyword, Risk: s.Risk.String(),
					Skipped: "dry run: the real run would be blocked (meta.would_be_blocked), so nothing was executed"})
			}
			rec["committed"] = false
			audit(st, name, nil, "", true, rec)
			out.P.Print(name, queryData{Conn: c.Name, Risk: plan.Risk.String(), Write: f.write, DryRun: true, Result: res}, nil)
			return nil
		}
	}
	db, closeDB, err := openDB(ctx, st, c, !f.write)
	if err != nil {
		return fail(err)
	}
	defer closeDB()
	if f.mariaAnalyze && dbx.IsMariaDB(ctx, db) {
		for i, st := range plan.Statements {
			if rest, ok := strings.CutPrefix(st.SQL, "EXPLAIN ANALYZE "); ok {
				plan.Statements[i].SQL = "ANALYZE " + rest
			}
		}
	}
	args := make([]any, len(f.args))
	for i, a := range f.args {
		args[i] = a
	}
	res, err := dbx.Run(ctx, db, c.Kind, plan, dbx.Options{Write: f.write, DryRun: g.dryRun, Limit: f.limit,
		MaxBytes: maxOutput(st), Timeout: connTimeout(c), Args: args})
	if err != nil {
		return fail(err)
	}
	var affected int64
	for _, r := range res.Results {
		if r.RowsAffected != nil {
			affected += *r.RowsAffected
		}
	}
	rec["rows_affected"] = affected
	rec["committed"] = res.Committed
	audit(st, name, nil, "", true, rec)
	return printQuery(name, c, plan, f, res)
}

// printQuery shows a query's result, with the conn's mask_columns hidden
// when personal data is.
func printQuery(name string, c *store.Conn, plan driver.SQLPlan, f dbFlags, res *dbx.Result) error {
	maskColumns(c, res)
	if f.csv || f.tsv {
		// through Redact like every other output: vault values, and for an
		// AI agent secrets and personal data, stay hidden in CSV too
		var b strings.Builder
		if err := writeDelimited(&b, res, f.tsv); err != nil {
			return err
		}
		_, err := io.WriteString(out.P.W, out.P.Redact(b.String()))
		return err
	}
	out.P.Print(name, queryData{Conn: c.Name, Risk: plan.Risk.String(), Write: f.write, DryRun: g.dryRun, Result: res}, nil)
	return nil
}

// sqlSecret matches the password literal in CREATE/ALTER USER and ROLE,
// SET PASSWORD and PASSWORD() so the audit log never stores it:
// PASSWORD 'x' (Postgres), IDENTIFIED [WITH plugin] BY 'x', SET PASSWORD
// [FOR u] = 'x' (MySQL).
var sqlSecret = regexp.MustCompile(`(?is)(\bPASSWORD\s*(?:FOR\s+\S+\s*)?=?\s*\(?\s*|\bIDENTIFIED\s+(?:WITH\s+\S+\s+)?BY\s+)('(?:[^'\\]|''|\\.)*'|"(?:[^"\\]|""|\\.)*"|\$[A-Za-z_]*\$.*?\$[A-Za-z_]*\$)`)

func redactSQL(q string) string {
	return sqlSecret.ReplaceAllString(q, "${1}'***'")
}
