package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
		Long: `Look at and query your databases. Add one with ` + "`komando db add`" + `.

Without --write every query runs in a read-only transaction (SQL Server: one
that is always rolled back), so nothing can change. With --write, try
--dry-run first: it runs the SQL and rolls it back, showing how many rows
would change.`,
	}
	c.AddCommand(connAddCmdFor("db"), dbQueryCmd(), dbSchemaCmd(), dbExplainCmd(), dbInfoCmd(), dbActivityCmd(), dbLocksCmd(), dbSizesCmd(), dbKillCmd(), dbUserCmd(), dbGrantCmd(false), dbGrantCmd(true), dbGrantsCmd(), dbShellCmd(), dbDumpCmd(), dbRestoreCmd())
	return c
}

type dbFlags struct {
	write bool
	limit int
	args  []string
	csv   bool
	tsv   bool
	// limitSet: --limit was given, so rows cut by it are what was asked for
	limitSet bool
	// mariaAnalyze: the SQL starts with EXPLAIN ANALYZE, which MariaDB
	// spells ANALYZE
	mariaAnalyze bool
	// showplan: db explain on SQL Server, Oracle and BigQuery (dbx.Options.Showplan)
	showplan string
	// maxBytes: --max-bytes, the most a BigQuery query may read ("" is the default)
	maxBytes string
}

func dbQueryCmd() *cobra.Command {
	var f dbFlags
	var file string
	c := &cobra.Command{
		Use:   "query CONN [SQL]",
		Short: "Run SQL; read-only unless --write",
		Long: `Runs SQL on a database and prints the rows. Without --write it only reads:
komando runs it in a read-only transaction, and stops it after 30s.`,
		Annotations: map[string]string{helpNotes: `More about db query:
A run stops after 30s unless --timeout (or the statement_timeout option in
the database URL) allows more. Placeholders take their values from
--arg, in order. --csv and --tsv print the rows for spreadsheets and scripts.
SQL that starts with a -- comment: pass it after -- or with -f -.

SQL Server has no read-only transaction: without --write komando rolls the
SQL back, and a statement it does not know as a read (a bare procedure
name, EXEC) needs --write. Its placeholders are @p1, @p2, ...

Oracle: placeholders are :1, :2, ... A PL/SQL block (BEGIN ... END;) runs
to the end of the text or to a line with only /, and needs --write and
--allow-dangerous. DDL (CREATE, ALTER, DROP, GRANT) commits on its own in
Oracle, so it needs --write, goes on its own, and a dry run only reports it.

ClickHouse has no transactions: without --write every request carries the
server's own readonly=1, and a statement that is not a read (INSERT, ALTER,
CREATE, ...) needs --write, goes on its own, and a dry run only reports it.
Placeholders are {p1:String}, {p2:UInt64}, ... (named p1, p2, with a type).

Snowflake has no read-only mode komando can switch on, and each statement
is a session of its own: without --write komando sends only what it rates
as a read, and a statement that is not a read needs --write, goes on its
own, and a dry run only reports it. Log in with a role that may only
read. Placeholders are ?.

BigQuery: each statement first goes as a dry run, which runs nothing and
says what BigQuery sees and how many bytes it would read (which is what
BigQuery bills). Without --write only a SELECT runs. A query that would
read more than --max-bytes (default 10GB) does not run, and the job
carries that cap too. A write needs --write, goes on its own, and
--write --dry-run shows BigQuery's dry run. Placeholders are ?; the values
go as STRING, so write CAST(? AS INT64) for a number.

On MongoDB the text is a command document in JSON, its first key
naming it ({"find": ...}, {"aggregate": ...}, {"update": ...}). komando rates
it as it rates SQL: what it does not know as a read needs --write. "$db"
picks another database than the URL's.`},
		Example: `  komando db query prod-db "select id, email from users order by id desc limit 10"
  komando db query mongo-db '{"find": "users", "filter": {"plan": "pro"}, "limit": 10}'   # MongoDB
  komando db query prod-db "select * from users where email = $1" --arg bob@example.com
  komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
  komando db query prod-db --file migration.sql --write --dry-run
  komando db query prod-db --csv "select * from orders" > orders.csv   # every row
  komando db query bq "select count(*) from shop.orders" --max-bytes 50GB   # BigQuery`,
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
			case len(args) == 1:
				return out.Usage("no SQL: give it as an argument, or with -f FILE (-f - reads stdin)")
			default:
				return out.Usage("give the SQL as an argument or with --file, not both")
			}
			if f.csv && f.tsv {
				return out.Usage("pick one of --csv and --tsv")
			}
			if (f.csv || f.tsv) && !cmd.Flags().Changed("limit") {
				f.limit = 0 // an export wants every row; --max-output still caps the size
			}
			f.limitSet = cmd.Flags().Changed("limit")
			if st, c, ok := mongoConn(args[0]); ok {
				return runMongoQuery(cmd.Context(), "db.query", st, c, q, f)
			}
			return runSQL(cmd.Context(), "db.query", args[0], q, f)
		},
	}
	f.bind(c)
	c.Flags().StringVarP(&file, "file", "f", "", "read SQL from a file ('-' for stdin)")
	c.Flags().BoolVar(&f.csv, "csv", false, "print every row as CSV (header first) instead of JSON or a table")
	c.Flags().BoolVar(&f.tsv, "tsv", false, "print every row as tab-separated values (header first)")
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
	c.Flags().IntVarP(&f.limit, "limit", "n", 500, "the most rows to return per statement (0 = no limit; --max-output caps the size too)")
	c.Flags().StringArrayVar(&f.args, "arg", nil, "value for a placeholder ($1 in postgres, ? in mysql/sqlite, @p1 in sqlserver, :1 in oracle, {p1:String} in clickhouse, ? in snowflake and bigquery); repeat in order")
	c.Flags().StringVar(&f.maxBytes, "max-bytes", "", "BigQuery: the most a query may read, which BigQuery bills by (default 10GB; 0 = no cap)")
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
			case "oracle": // EXPLAIN PLAN and DBMS_XPLAN
				if analyze {
					return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "drop --analyze: db explain shows Oracle's plan with its estimated rows",
						"db explain --analyze is not available for oracle")
				}
				f.showplan = "text"
			case "clickhouse": // EXPLAIN plans without running; there is no EXPLAIN ANALYZE
				if analyze {
					return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "drop --analyze: ClickHouse has no EXPLAIN ANALYZE; a finished query's real numbers are in system.query_log",
						"db explain --analyze is not available for clickhouse")
				}
				prefix = "EXPLAIN indexes = 1 "
			case "snowflake": // EXPLAIN compiles without running
				if analyze {
					return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "drop --analyze: Snowflake's real numbers for a finished query are in its query profile (GET_QUERY_OPERATOR_STATS)",
						"db explain --analyze is not available for snowflake")
				}
				prefix = "EXPLAIN "
			case "bigquery": // the dry run: statement type, bytes it would read, tables
				if analyze {
					return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "drop --analyze: db explain shows BigQuery's dry run; a finished job's stages are in INFORMATION_SCHEMA.JOBS (job_stages)",
						"db explain --analyze is not available for bigquery")
				}
				f.showplan = "text"
			case "sqlserver": // no EXPLAIN: a SET SHOWPLAN_TEXT (or STATISTICS PROFILE) session setting
				f.showplan = map[bool]string{false: "text", true: "profile"}[analyze]
			default: // MongoDB, and kinds without SQL: the classifier says how
				_, err := driver.ClassifySQL(c.Kind, args[1])
				return err
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
			if c.Kind == "mongodb" {
				return runMongoSchema(cmd.Context(), st, c, args[1:])
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
	if len(d.Tables) == 0 {
		return "no tables found (the database is empty, or the conn's user cannot see them)\n"
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

// dbTimeout is --timeout, or 30s without it.
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
	if a.Target.Kind.Name == "sqlite" && !readOnly && g.dryRun {
		// a --write run creates a missing file; a dry run must not
		if _, err := os.Stat(dbx.SQLitePath(a.Target)); errors.Is(err, fs.ErrNotExist) {
			a.Close()
			return nil, nil, out.Errf(out.ExitConnect, "DB_CONNECT",
				"check the path in the conn URL (`komando conn show "+c.Name+"`); without --dry-run, --write creates a new, empty database there",
				"cannot open %s: the file does not exist, and a dry run does not create it", a.Target.Path)
		}
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
		if r.BytesProcessed != nil && r.Skipped == "" {
			fmt.Fprintf(&sb, "(BigQuery read %s)\n", humanBytes(*r.BytesProcessed))
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
	plan, err := classifyQuery(c.Kind, query, f)
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
		MaxBytes: maxOutput(st), Timeout: connTimeout(c), Args: args, Showplan: f.showplan, MaxBilled: f.maxBilled(c.Kind)})
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
		if _, err := io.WriteString(out.P.W, out.P.Redact(b.String())); err != nil {
			return err
		}
		return delimitedCut(res, f.limitSet)
	}
	out.P.Print(name, queryData{Conn: c.Name, Risk: plan.Risk.String(), Write: f.write, DryRun: g.dryRun, Result: res}, nil)
	return nil
}

// delimitedCut fails a CSV or TSV export that lost rows the person did not
// ask to drop, so a script does not take a cut file for the whole table.
// The error goes to stderr as text: stdout holds the rows.
func delimitedCut(res *dbx.Result, limitSet bool) error {
	for _, r := range res.Results {
		switch {
		case r.Truncated == "bytes":
			out.P.Format = "text"
			return out.Errf(out.ExitError, "OUTPUT_TRUNCATED", "raise --max-output (bytes, e.g. --max-output 104857600), or select fewer rows or columns",
				"the export stopped at %d rows: the output size cap (--max-output) was reached", r.RowCount)
		case r.Truncated == "rows" && limitSet:
			fmt.Fprintf(os.Stderr, "note: stopped at %d rows (--limit); -n 0 exports every row\n", r.RowCount)
		}
	}
	return nil
}

// sqlGap is the space between two words, which may hold comments
// (IDENTIFIED/**/BY).
const sqlGap = `(?:\s|/\*.*?\*/|--[^\n]*\n)+`

// sqlSecret matches the password literal in CREATE/ALTER USER and ROLE,
// SET PASSWORD and PASSWORD() so the audit log never stores it:
// PASSWORD 'x' (Postgres), IDENTIFIED [WITH plugin] BY 'x', SET PASSWORD
// [FOR u] = 'x' (MySQL), PASSWORD = N'x' (SQL Server), IDENTIFIED BY
// VALUES 'hash' (Oracle).
var sqlSecret = regexp.MustCompile(`(?is)(\bPASSWORD\s*(?:FOR\s+\S+\s*)?=?\s*\(?\s*N?|\bIDENTIFIED` + sqlGap + `(?:WITH\s+\S+\s+)?BY` + sqlGap + `(?:VALUES` + sqlGap + `)?)('(?:[^'\\]|''|\\.)*'|"(?:[^"\\]|""|\\.)*"|\$[A-Za-z_]*\$.*?\$[A-Za-z_]*\$)`)

// oraSecret is Oracle's IDENTIFIED BY password without quotes.
var oraSecret = regexp.MustCompile(`(?is)(\bIDENTIFIED` + sqlGap + `BY` + sqlGap + `)([A-Za-z][A-Za-z0-9_$#]*)`)

// oraOld is the old password in Oracle's ALTER USER u IDENTIFIED BY new
// REPLACE old, once the new one is hidden.
var oraOld = regexp.MustCompile(`(?is)(\bIDENTIFIED` + sqlGap + `BY` + sqlGap + `(?:'\*\*\*'|\*\*\*)` + sqlGap + `REPLACE` + sqlGap + `)('(?:[^']|'')*'|"(?:[^"]|"")*"|[A-Za-z][A-Za-z0-9_$#]*)`)

func redactSQL(q string) string {
	q = sqlSecret.ReplaceAllString(q, "${1}'***'")
	q = oraSecret.ReplaceAllStringFunc(q, func(m string) string {
		p := oraSecret.FindStringSubmatch(m)
		if strings.EqualFold(p[2], "PASSWORD") || strings.EqualFold(p[2], "VALUES") { // MySQL's IDENTIFIED BY PASSWORD 'hash'
			return m
		}
		return p[1] + "***"
	})
	return oraOld.ReplaceAllStringFunc(q, func(m string) string {
		p := oraOld.FindStringSubmatch(m)
		if p[2][0] == '\'' || p[2][0] == '"' {
			return p[1] + "'***'"
		}
		return p[1] + "***"
	})
}

// maxBytesFlag reads --max-bytes for dbx.Options.MaxBilled: 0 for the
// default, -1 for no cap. Only BigQuery bills by the bytes a query reads.
func maxBytesFlag(kind, s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	if kind != "bigquery" {
		return 0, out.Usage("--max-bytes is for BigQuery conns, which bill by the bytes a query reads; drop it")
	}
	n, err := dbx.ParseBytes(s)
	if n == 0 && err == nil {
		n = -1
	}
	return n, err
}

// maxBilled is --max-bytes as maxBytesFlag reads it (classifyQuery has
// checked it).
func (f dbFlags) maxBilled(kind string) int64 {
	n, _ := maxBytesFlag(kind, f.maxBytes)
	return n
}

// classifyQuery is driver.ClassifySQL for runSQL, after a check of
// --max-bytes. Under db explain on SQL Server and Oracle the statements
// are only planned (SET SHOWPLAN_TEXT, EXPLAIN PLAN), and on BigQuery
// dry-run, so a change that the rollback would undo reads.
func classifyQuery(kind, query string, f dbFlags) (driver.SQLPlan, error) {
	if _, err := maxBytesFlag(kind, f.maxBytes); err != nil {
		return driver.SQLPlan{}, err
	}
	plan, err := driver.ClassifySQL(kind, query)
	if err != nil || f.showplan != "text" {
		return plan, err
	}
	return driver.PlanOnly(plan), nil
}
