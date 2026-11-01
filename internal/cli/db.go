package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"text/tabwriter"
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
	c.AddCommand(dbQueryCmd(), dbSchemaCmd(), dbExplainCmd(), dbDumpCmd(), dbRestoreCmd())
	return c
}

type dbFlags struct {
	write bool
	limit int
	args  []string
}

func dbQueryCmd() *cobra.Command {
	var f dbFlags
	var file string
	c := &cobra.Command{
		Use:   "query CONN [SQL]",
		Short: "Run SQL; read-only unless --write",
		Example: `  komando db query prod-db "select id, email from users order by id desc limit 10"
  komando db query prod-db "select * from users where email = $1" --arg bob@example.com
  komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
  komando db query prod-db --file migration.sql --write --dry-run`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var q string
			switch {
			case len(args) == 2 && file == "":
				q = args[1]
			case len(args) == 1 && file != "":
				b, err := readFileOrStdin(file)
				if err != nil {
					return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "cannot read %s: %v", file, err)
				}
				q = string(b)
			default:
				return out.Usage("give the SQL as an argument or with --file (not both)")
			}
			return runSQL(cmd.Context(), "db.query", args[0], q, f)
		},
	}
	f.bind(c)
	c.Flags().StringVarP(&file, "file", "f", "", "read SQL from a file ('-' for stdin)")
	return c
}

func (f *dbFlags) bind(c *cobra.Command) {
	c.Flags().BoolVar(&f.write, "write", false, "allow changes (runs in a normal transaction; combine with --dry-run to roll back)")
	c.Flags().IntVar(&f.limit, "limit", 500, "max rows returned per statement (0 = no limit; output size is capped by --max-output too)")
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
			c, err := singleConn(st, args[0], "sql")
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
					prefix = "EXPLAIN ANALYZE "
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
			c, err := singleConn(st, args[0], "sql")
			if err != nil {
				return err
			}
			db, closeDB, err := openDB(cmd.Context(), st, c, true)
			if err != nil {
				return err
			}
			defer closeDB()
			tables, err := dbx.Schema(cmd.Context(), db, c.Kind, args[1:], dbTimeout())
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
		tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "TABLE\tTYPE\tROWS (EST.)")
		for _, t := range d.Tables {
			rows := "-"
			if t.RowEstimate != nil {
				rows = fmt.Sprint(*t.RowEstimate)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", qualified(t), t.Type, rows)
		}
		tw.Flush()
		return sb.String()
	}
	for i, t := range d.Tables {
		if i > 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%s (%s)\n", qualified(t), t.Type)
		tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
		for _, c := range t.Columns {
			var notes []string
			if c.PrimaryKey {
				notes = append(notes, "primary key")
			}
			if !c.Nullable {
				notes = append(notes, "not null")
			}
			if c.Default != nil {
				notes = append(notes, "default "+*c.Default)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", c.Name, c.Type, strings.Join(notes, ", "))
		}
		tw.Flush()
		for _, ix := range t.Indexes {
			fmt.Fprintf(&sb, "  index %s\n", dash(ix.Definition))
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
// given family (sql, redis, s3).
func singleConn(st *store.State, expr, family string) (*store.Conn, error) {
	cs, err := resolveConns(st, expr)
	if err != nil {
		return nil, err
	}
	if len(cs) != 1 {
		return nil, out.Usage("target %q matched %d conns; this command needs exactly one", expr, len(cs))
	}
	t, err := driver.Parse(cs[0].URL)
	if err != nil {
		return nil, err
	}
	if err := t.Need(family); err != nil {
		return nil, err
	}
	return cs[0], nil
}

func dbTimeout() time.Duration {
	if g.timeout > 0 {
		return g.timeout
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
		return nil, nil, err
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
			tw := tabwriter.NewWriter(&sb, 0, 2, 2, ' ', 0)
			names := make([]string, len(r.Columns))
			for j, c := range r.Columns {
				names[j] = c.Name
			}
			fmt.Fprintln(tw, strings.Join(names, "\t"))
			for _, row := range r.Rows {
				cells := make([]string, len(row))
				for j, v := range row {
					cells[j] = cellText(v, wide)
				}
				fmt.Fprintln(tw, strings.Join(cells, "\t"))
			}
			tw.Flush()
			fmt.Fprintf(&sb, "(%d row%s%s)\n", r.RowCount, plural(r.RowCount), map[bool]string{true: ", truncated: add LIMIT/WHERE or raise --limit"}[r.Truncated])
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

func cellText(v any, wide bool) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case string:
		x = strings.NewReplacer("\t", `\t`, "\n", `\n`, "\r", `\r`).Replace(x)
		if len(x) > 80 && !wide {
			x = x[:77] + "..."
		}
		return x
	case map[string]string:
		return "<binary>"
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
	c, err := singleConn(st, connExpr, "sql")
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
		rec["sql"] = query
	}
	if len(f.args) > 0 {
		rec["args"] = len(f.args) // values may be personal data; record only how many
	}
	fail := func(err error) error {
		rec["error"] = toErr(err).Code
		audit(st, name, nil, "", false, rec)
		return err
	}
	if !f.write && plan.NeedsWrite() {
		e := out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG",
			"this SQL changes data; re-run with --write (try --write --dry-run first)",
			"%s statement needs --write", plan.Risk)
		if len(plan.RuleIDs) > 0 {
			e.Message += fmt.Sprintf(" (and --allow-dangerous: %s)", strings.Join(plan.Reasons, "; "))
		}
		return fail(e)
	}
	if f.write {
		if err := guardConns([]*store.Conn{c}, plan.Verdict); err != nil {
			return fail(err)
		}
	}
	db, closeDB, err := openDB(ctx, st, c, !f.write)
	if err != nil {
		return fail(err)
	}
	defer closeDB()
	args := make([]any, len(f.args))
	for i, a := range f.args {
		args[i] = a
	}
	res, err := dbx.Run(ctx, db, c.Kind, plan, dbx.Options{Write: f.write, DryRun: g.dryRun, Limit: f.limit,
		MaxBytes: maxOutput(st), Timeout: dbTimeout(), Args: args})
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
	out.P.Print(name, queryData{Conn: c.Name, Risk: plan.Risk.String(), Write: f.write, DryRun: g.dryRun, Result: res}, nil)
	return nil
}
