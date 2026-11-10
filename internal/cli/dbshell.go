package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// db shell is komando's own SQL shell for a person at a terminal: no psql,
// mysql or sqlite3 needed. Every statement goes through the same checks as
// db query (classified, read-only unless --write, destructive SQL needs
// --allow-dangerous) and is audited. Agents use db query instead.

func dbShellCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "shell CONN",
		Short: "Interactive SQL shell for people (read-only unless --write)",
		Long: `Opens komando's own SQL shell on CONN (PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, ClickHouse, Snowflake, BigQuery or SQLite),
through its --via path when it has one. Nothing else needs to be installed.

Each statement ends with ; (an Oracle PL/SQL block with a line holding
only /) and runs with the checks of db query: read-only
unless the shell was started with --write, destructive statements only with
--allow-dangerous, and every statement is audited. A statement runs in its
own transaction. A protected conn asks first.

Inside: \q quits, \? lists the commands, \d [TABLE] shows tables or one
table, \l databases, \dn schemas, \du roles, \x switches expanded rows,
\timing shows how long each statement took, \i FILE runs a file, and a
statement ending in \G is shown expanded. Up and down arrows recall lines.`,
		Example: `  komando db shell prod-db
  komando db shell staging-db --write`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBShell(cmd.Context(), args[0], write)
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow changes in this session")
	return c
}

func runDBShell(ctx context.Context, connExpr string, write bool) error {
	if !interactive() {
		return out.Errf(out.ExitUsage, "NEEDS_TERMINAL",
			"agents and scripts use `komando db query CONN \"SQL\"`, which returns JSON and checks every statement",
			"db shell is interactive and needs a person at a terminal")
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "db")
	if err != nil {
		return err
	}
	t, err := driver.Parse(c.URL)
	if err != nil {
		return err
	}
	// a protected conn asks before any shell: inside, anything can be typed
	if write || protectedConn(st, c) {
		if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: driver.RiskWrite}); err != nil {
			return err
		}
	}
	rec := map[string]any{"conns": []string{c.Name}, "write": write, "client": "komando"}
	if g.dryRun { // before any VPN, SSH or database contact
		audit(st, "db.shell", nil, "", true, rec)
		out.P.Print("db.shell", map[string]any{"conn": c.Name, "kind": t.Kind.Name, "via": c.Via, "write": write, "dry_run": true}, nil)
		return nil
	}
	mode := "read-only"
	if write {
		mode = "read-write"
	}
	showStatus(statusLine{What: t.Kind.Name, Target: c.Name, Detail: mode, Route: connRoute(st, c), Protected: protectedConn(st, c)})
	db, closeDB, err := openDB(ctx, st, c, !write)
	if err != nil {
		audit(st, "db.shell", nil, "", false, map[string]any{"conns": []string{c.Name}, "error": toErr(err).Code})
		return err
	}
	defer func() { closeDB() }() // the connection \write opened, when it did
	audit(st, "db.shell", nil, "", true, rec)

	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, old)
	tty := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}
	started := time.Now()
	tm := term.NewTerminal(tty, "")
	if w, h, err := term.GetSize(fd); err == nil {
		tm.SetSize(w, h)
	}
	sh := &sqlShell{db: db, st: st, conn: c, kind: c.Kind, write: write, term: tm}
	// \write and \read open the database again: the read-only mode is the
	// database's own (a read-only transaction), not only komando's check
	sh.reopen = func(w bool) error {
		ndb, nclose, err := openDB(ctx, st, c, !w)
		if err != nil {
			return err
		}
		closeDB()
		sh.db, closeDB = ndb, nclose
		return nil
	}
	sh.run(ctx)
	term.Restore(fd, old)
	showExit(c.Name, 0, false, time.Since(started))
	return nil
}

// sqlShell reads statements from a terminal and runs them.
type sqlShell struct {
	db       *sql.DB
	st       *store.State
	conn     *store.Conn
	kind     string
	write    bool
	expanded bool
	timing   bool
	term     interface {
		ReadLine() (string, error)
		SetPrompt(string)
		io.Writer
	}
	reopen func(write bool) error // connect again, read-write or read-only
}

// ask asks the person a question inside the shell (the terminal is the
// shell's own) and returns the answer; Ctrl-C or Ctrl-D is an empty one.
func (s *sqlShell) ask(q string) string {
	s.term.SetPrompt(q)
	line, err := s.term.ReadLine()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// switchWrite is \write: changes need a yes first (on a protected conn
// too, as starting the shell with --write asks), and \write again goes
// back to read-only.
func (s *sqlShell) switchWrite() {
	name := s.conn.Name
	if s.write {
		if err := s.reopen(false); err != nil {
			s.printf("error: %s\n", toErr(err).Message)
			return
		}
		s.write = false
		s.printf("Read-only again.\n")
		return
	}
	q := fmt.Sprintf("Allow changes to %s for the rest of this shell? [y/N] ", name)
	if protectedConn(s.st, s.conn) {
		q = fmt.Sprintf("%s is protected. Allow changes for the rest of this shell? [y/N] ", name)
	}
	if a := strings.ToLower(s.ask(q)); a != "y" && a != "yes" {
		s.printf("Still read-only.\n")
		return
	}
	if err := s.reopen(true); err != nil {
		s.printf("error: %s\n", toErr(err).Message)
		return
	}
	s.write = true
	audit(s.st, "db.shell", nil, "", true, map[string]any{"conns": []string{name}, "write": true, "switched": true})
	s.printf("Changes are allowed now. \\write again goes back to read-only.\n")
}

func (s *sqlShell) printf(format string, a ...any) {
	fmt.Fprintf(s.term, format, a...)
}

func (s *sqlShell) prompt(cont bool) {
	p := s.conn.Name
	if s.write {
		p += " (write)"
	}
	if cont {
		s.term.SetPrompt(strings.Repeat(" ", len(p)-1) + "-> ")
		return
	}
	s.term.SetPrompt(p + "> ")
}

func (s *sqlShell) run(ctx context.Context) {
	s.printf("komando SQL shell on %s (%s). \\? for help, \\q to quit.\n", s.conn.Name, s.kind)
	var buf strings.Builder
	for {
		s.prompt(buf.Len() > 0)
		line, err := s.term.ReadLine()
		if err != nil { // Ctrl-D or Ctrl-C
			if buf.Len() > 0 {
				buf.Reset()
				s.printf("(input cleared)\n")
				continue
			}
			s.printf("\n")
			return
		}
		trimmed := strings.TrimSpace(line)
		if buf.Len() == 0 && (trimmed == "quit" || trimmed == "exit") {
			return
		}
		if buf.Len() == 0 && strings.HasPrefix(trimmed, `\`) {
			if s.meta(ctx, trimmed) {
				return
			}
			continue
		}
		if buf.Len() > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(line)
		text := strings.TrimSpace(buf.String())
		expanded := false
		if strings.HasSuffix(text, `\G`) {
			text, expanded = strings.TrimSpace(strings.TrimSuffix(text, `\G`)), true
		} else if !shellDone(s.kind, text) {
			continue
		}
		buf.Reset()
		if text == "" || text == ";" {
			continue
		}
		s.exec(ctx, text, expanded || s.expanded)
	}
}

// meta runs a backslash command; true means quit.
func (s *sqlShell) meta(ctx context.Context, line string) bool {
	cmd, arg, _ := strings.Cut(line, " ")
	arg = strings.TrimSpace(arg)
	switch cmd {
	case `\q`, `\quit`:
		return true
	case `\write`:
		s.switchWrite()
	case `\?`, `\h`, `\help`:
		s.printf("%s", shellHelp)
	case `\x`:
		s.expanded = !s.expanded
		s.printf("Expanded display is %s.\n", map[bool]string{true: "on", false: "off"}[s.expanded])
	case `\timing`:
		s.timing = !s.timing
		s.printf("Timing is %s.\n", map[bool]string{true: "on", false: "off"}[s.timing])
	case `\conninfo`:
		s.printf("Connected to %s (%s), %s.\n", s.conn.Name, s.kind, map[bool]string{true: "read-write", false: "read-only"}[s.write])
	case `\d`, `\dt`, `\d+`:
		var names []string
		if arg != "" {
			names = []string{arg}
		}
		tables, err := dbx.Schema(ctx, s.db, s.kind, names, connTimeout(s.conn))
		if err != nil {
			s.printf("error: %s\n", toErr(err).Message)
			return false
		}
		if len(tables) == 0 {
			s.printf("Did not find any relation%s.\n", map[bool]string{true: " named " + arg, false: "s"}[arg != ""])
			return false
		}
		s.printf("%s", schemaData{Tables: tables}.Text())
	case `\l`, `\list`:
		s.exec(ctx, map[string]string{"postgres": "SELECT datname AS name FROM pg_database WHERE NOT datistemplate ORDER BY 1",
			"mysql": "SHOW DATABASES", "sqlite": "PRAGMA database_list", "sqlserver": "SELECT name FROM sys.databases ORDER BY 1",
			"oracle": "SELECT name, open_mode FROM v$pdbs ORDER BY 1", "clickhouse": "SHOW DATABASES", "snowflake": "SHOW DATABASES",
			"bigquery": bqDatasets}[s.kind], s.expanded)
	case `\dn`:
		s.exec(ctx, map[string]string{"postgres": "SELECT nspname AS name FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema' ORDER BY 1",
			"mysql": "SHOW DATABASES", "sqlite": "PRAGMA database_list", "sqlserver": "SELECT name FROM sys.schemas WHERE schema_id < 16384 ORDER BY 1",
			"oracle": "SELECT username AS name FROM all_users WHERE oracle_maintained = 'N' ORDER BY 1", "clickhouse": "SHOW DATABASES",
			"snowflake": "SHOW SCHEMAS", "bigquery": bqDatasets}[s.kind], s.expanded)
	case `\du`:
		q := map[string]string{"postgres": "SELECT rolname AS role, rolsuper AS superuser, rolcanlogin AS login FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY 1",
			"mysql":      "SELECT user, host FROM mysql.user ORDER BY 1, 2",
			"sqlserver":  "SELECT name, LOWER(type_desc) AS type FROM sys.database_principals WHERE type IN ('S', 'U', 'G', 'E', 'X', 'R') ORDER BY 1",
			"oracle":     "SELECT username AS name, account_status AS status FROM dba_users WHERE oracle_maintained = 'N' ORDER BY 1",
			"clickhouse": "SELECT name, 'user' AS type FROM system.users UNION ALL SELECT name, 'role' FROM system.roles ORDER BY 1",
			"snowflake":  "SHOW USERS"}[s.kind]
		if q == "" {
			s.printf("%s\n", map[string]string{"sqlite": "SQLite has no roles.", "bigquery": "BigQuery's users and roles are Google Cloud IAM."}[s.kind])
			return false
		}
		s.exec(ctx, q, s.expanded)
	case `\i`, `\include`:
		b, err := readLocalFile(expandHome(arg))
		if err != nil {
			s.printf("error: %v\n", err)
			return false
		}
		s.exec(ctx, string(b), s.expanded)
	default:
		s.printf("Invalid command %s. Try \\? for help.\n", cmd)
	}
	return false
}

// bqDatasets lists BigQuery datasets (in the jobs' location).
const bqDatasets = "SELECT schema_name AS name, location FROM INFORMATION_SCHEMA.SCHEMATA ORDER BY 1"

const shellHelp = `  \q            quit (also quit, exit, Ctrl-D)
  \write        allow changes (asks first); again to go back to read-only
  \d [TABLE]    tables, or one table's columns, indexes and constraints
  \l            databases
  \dn           schemas
  \du           roles
  \x            switch expanded rows on and off (or end a statement with \G)
  \timing       show how long each statement took
  \i FILE       run the statements in FILE
  \conninfo     where you are connected
`

// exec classifies, checks, runs and audits one input.
func (s *sqlShell) exec(ctx context.Context, text string, expanded bool) {
	plan, err := driver.ClassifySQL(s.kind, text)
	if err != nil {
		s.printf("error: %s\n", toErr(err).Message)
		return
	}
	if !s.write && plan.NeedsWrite() {
		s.printf("error: this %s statement changes data; the shell is read-only (\\write allows changes)\n", plan.Risk)
		return
	}
	if plan.Risk >= driver.RiskDestructive && !dangerOK() {
		// as on the command line, a person confirms by typing the name
		if s.ask(fmt.Sprintf("Dangerous: %s. Type %s to run it: ", strings.Join(plan.Reasons, "; "), s.conn.Name)) != s.conn.Name {
			s.printf("Not run.\n")
			return
		}
	}
	rec := map[string]any{"conns": []string{s.conn.Name}, "risk": plan.Risk.String(), "write": s.write, "shell": true}
	switch s.st.Settings.AuditSQL {
	case "hash":
		sum := sha256.Sum256([]byte(text))
		rec["sql_sha256"] = hex.EncodeToString(sum[:])
	case "off":
	default:
		rec["sql"] = redactSQL(text)
	}
	start := time.Now()
	res, err := dbx.Run(ctx, s.db, s.kind, plan, dbx.Options{Write: s.write, Limit: 10000, MaxBytes: 64 << 20, Timeout: connTimeout(s.conn)})
	took := time.Since(start)
	if err != nil {
		rec["error"] = toErr(err).Code
		audit(s.st, "db.shell", nil, "", false, rec)
		e := toErr(err)
		s.printf("error: %s\n", e.Message)
		var oe *out.Error
		if errors.As(err, &oe) && oe.Hint != "" {
			s.printf("hint: %s\n", oe.Hint)
		}
		return
	}
	audit(s.st, "db.shell", nil, "", true, rec)
	if expanded {
		s.printf("%s", expandedText(res))
	} else {
		s.printf("%s", queryData{Conn: s.conn.Name, Result: res}.Text())
	}
	if s.timing {
		s.printf("Time: %.3f ms\n", float64(took.Microseconds())/1000)
	}
}

// expandedText shows each row as "column | value" lines, like psql's \x.
func expandedText(res *dbx.Result) string {
	var b strings.Builder
	for _, r := range res.Results {
		if r.Columns == nil {
			b.WriteString(queryData{Result: &dbx.Result{Results: []dbx.StatementResult{r}}}.Text())
			continue
		}
		w := 0
		for _, c := range r.Columns {
			w = max(w, displayWidth(c.Name))
		}
		for i, row := range r.Rows {
			fmt.Fprintf(&b, "-[ RECORD %d ]%s\n", i+1, strings.Repeat("-", max(4, w)))
			for j, v := range row {
				fmt.Fprintf(&b, "%s%s | %s\n", r.Columns[j].Name, strings.Repeat(" ", w-displayWidth(r.Columns[j].Name)), cellText(v, true))
			}
		}
		fmt.Fprintf(&b, "(%d row%s)\n", r.RowCount, plural(r.RowCount))
	}
	return b.String()
}

// shellDone reports whether text is a whole statement to run: one ending
// in ; or, for an Oracle PL/SQL block, a last line with only /.
func shellDone(kind, text string) bool {
	if kind == "oracle" && driver.OracleBlock(text) {
		lines := strings.Split(text, "\n")
		return strings.TrimSpace(lines[len(lines)-1]) == "/"
	}
	if kind == "oracle" {
		return driver.OracleDone(text)
	}
	return statementDone(text)
}

// statementDone reports whether text ends with ; outside quotes, quoted
// names, dollar quotes and comments.
func statementDone(text string) bool {
	last := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			j := i + 1
			for j < len(text) {
				if text[j] == '\\' && c != '"' {
					j += 2
					continue
				}
				if text[j] == c {
					if j+1 < len(text) && text[j+1] == c { // doubled quote
						j += 2
						continue
					}
					break
				}
				j++
			}
			if j >= len(text) {
				return false // still inside the quote
			}
			i, last = j, c
		case c == '-' && i+1 < len(text) && text[i+1] == '-', c == '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return false
			}
			i += end + 3
		case c == '$':
			j := i + 1
			for j < len(text) && (text[j] == '_' || text[j] >= 'a' && text[j] <= 'z' || text[j] >= 'A' && text[j] <= 'Z' || text[j] >= '0' && text[j] <= '9') {
				j++
			}
			if j < len(text) && text[j] == '$' {
				tag := text[i : j+1]
				end := strings.Index(text[j+1:], tag)
				if end < 0 {
					return false
				}
				i, last = j+end+len(tag), '$'
				continue
			}
			last = c
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			last = c
		}
	}
	return last == ';'
}
