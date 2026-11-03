package cli

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Backups always land on (and restore from) this computer. The database's
// own tool (pg_dump, mysqldump, psql, mysql) runs on the conn's --via host
// when it has one, otherwise here, and the data is streamed over SSH. The
// password reaches the tool through its environment, never its arguments.

type dumpTool struct {
	dump, restore []string
	restoreCustom []string // postgres: pg_restore for --format custom archives
	passwordEnv   string
	pkg           string // Debian/Ubuntu package that provides the tools, for hints
	tls           string // mysql: the URL's tls= setting, mapped to client flags at run time
}

// mysqlTLSFlags maps the URL's tls= setting to the client's flags. MySQL
// and MariaDB clients spell them differently; version is `--version` output.
func mysqlTLSFlags(tls, version string) []string {
	if tls == "" {
		return nil
	}
	if strings.Contains(version, "MariaDB") {
		return map[string][]string{
			"true":        {"--ssl", "--ssl-verify-server-cert"},
			"skip-verify": {"--ssl", "--skip-ssl-verify-server-cert"},
			"preferred":   {"--ssl"},
			"false":       {"--skip-ssl"},
		}[tls]
	}
	return map[string][]string{
		"true":        {"--ssl-mode=VERIFY_IDENTITY"},
		"skip-verify": {"--ssl-mode=REQUIRED"},
		"preferred":   {"--ssl-mode=PREFERRED"},
		"false":       {"--ssl-mode=DISABLED"},
	}[tls]
}

func toolsFor(c *store.Conn, t driver.Target) (dumpTool, error) {
	switch t.Kind.Name {
	case "postgres":
		// libpq accepts the conn URL as is (it never contains a password)
		return dumpTool{
			dump:          []string{"pg_dump", "--dbname", c.URL},
			restore:       []string{"psql", "--dbname", c.URL, "--single-transaction", "--set", "ON_ERROR_STOP=1", "--quiet", "--no-psqlrc"},
			restoreCustom: []string{"pg_restore", "--dbname", c.URL, "--single-transaction", "--exit-on-error", "--no-password"},
			passwordEnv:   "PGPASSWORD", pkg: "postgresql-client",
		}, nil
	case "mysql":
		if t.Database == "" {
			return dumpTool{}, out.Usage("the conn URL has no database name; add it (mysql://user@host:3306/NAME) to dump or restore")
		}
		host, port, _ := net.SplitHostPort(t.Address)
		conn := []string{"--host", host, "--port", port}
		if t.User != "" {
			conn = append(conn, "--user", t.User)
		}
		return dumpTool{
			dump:        append(append([]string{"mysqldump"}, conn...), "--single-transaction", "--routines", "--triggers", "--no-tablespaces", t.Database),
			restore:     append(append([]string{"mysql"}, conn...), t.Database),
			passwordEnv: "MYSQL_PWD", pkg: "mysql-client",
			tls: t.TLS,
		}, nil
	}
	return dumpTool{}, out.Usage("%s conns have no dump tool", t.Kind.Name)
}

// dumpOpts narrows or reshapes a dump.
type dumpOpts struct {
	format     string // plain (SQL) or custom (pg_dump -Fc)
	schemaOnly bool
	tables     []string
}

// args adds the options to the tool's command line.
func (o dumpOpts) args(kind string, base []string) ([]string, error) {
	argv := append([]string(nil), base...)
	switch kind {
	case "postgres":
		if o.format == "custom" {
			argv = append(argv, "--format=custom")
		}
		if o.schemaOnly {
			argv = append(argv, "--schema-only")
		}
		for _, t := range o.tables {
			argv = append(argv, "--table="+t)
		}
	case "mysql":
		if o.format == "custom" {
			return nil, out.Usage("--format custom is a PostgreSQL archive; MySQL dumps are SQL")
		}
		if o.schemaOnly {
			argv = append(argv[:len(argv)-1], "--no-data", argv[len(argv)-1])
		}
		argv = append(argv, o.tables...) // mysqldump DB TABLE...
	}
	return argv, nil
}

func dbDumpCmd() *cobra.Command {
	var to string
	var o dumpOpts
	c := &cobra.Command{
		Use:   "dump CONN --to FILE",
		Short: "Back up a database to a file on this computer (.gz to compress)",
		Long: `Runs pg_dump or mysqldump (on the conn's --via host when set, otherwise here)
and saves plain SQL to FILE on this computer. FILE ending in .gz is compressed.
PostgreSQL can also write its own archive with --format custom (compressed,
restored with pg_restore). --table and --schema-only narrow the dump. SQLite
conns are copied as a database file instead. An existing FILE is never
overwritten. The file holds your data: it is created readable only by you.`,
		Example: `  komando db dump prod-db --to prod-2026-11-02.sql.gz
  komando db dump prod-db --to prod.dump --format custom
  komando db dump prod-db --to orders.sql --table public.orders --table public.order_items
  komando db dump prod-db --to schema.sql --schema-only
  komando db dump local --to backup.db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return out.Usage("--to FILE is required")
			}
			if o.format != "plain" && o.format != "custom" {
				return out.Usage("--format is plain (SQL) or custom (PostgreSQL archive)")
			}
			if o.format == "custom" && strings.HasSuffix(to, ".gz") {
				return out.Usage("a custom archive is already compressed; drop the .gz")
			}
			return runDump(cmd.Context(), args[0], to, o)
		},
	}
	c.Flags().StringVar(&to, "to", "", "file to create on this computer")
	c.Flags().StringVar(&o.format, "format", "plain", "plain (SQL) or custom (PostgreSQL archive for pg_restore)")
	c.Flags().BoolVar(&o.schemaOnly, "schema-only", false, "tables, indexes and functions, no rows")
	c.Flags().StringArrayVar(&o.tables, "table", nil, "only this table (repeatable; SCHEMA.TABLE on PostgreSQL)")
	return c
}

func dbRestoreCmd() *cobra.Command {
	var from string
	c := &cobra.Command{
		Use:   "restore CONN --from FILE",
		Short: "Load a backup into a database: SQL, .sql.gz or a PostgreSQL archive (needs --allow-dangerous)",
		Long: `Runs the SQL in FILE (from ` + "`db dump`" + ` or any plain SQL file; .gz is read
compressed) with psql or mysql. A PostgreSQL archive (` + "`db dump --format custom`" + `)
is recognised by its content and loaded with pg_restore. A restore can overwrite existing data, so it
needs --allow-dangerous, plus --yes on a protected conn. The whole file is
checked first: client commands that could run programs (\! or system) are
refused. PostgreSQL restores run in one transaction: on any error nothing
changes.`,
		Example: `  komando db restore staging-db --from prod-2026-11-02.sql.gz --allow-dangerous`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return out.Usage("--from FILE is required")
			}
			return runRestore(cmd.Context(), args[0], from)
		},
	}
	c.Flags().StringVar(&from, "from", "", "SQL file on this computer")
	return c
}

type transferData struct {
	Conn   string   `json:"conn"`
	File   string   `json:"file"`
	Bytes  int64    `json:"bytes"`
	Tool   []string `json:"tool,omitempty"`
	RunsOn string   `json:"runs_on"` // "local" or the --via host
	DryRun bool     `json:"dry_run,omitempty"`
}

func (d transferData) Text() string {
	if d.DryRun {
		return fmt.Sprintf("dry run: would run %s on %s for %s", strings.Join(d.Tool, " "), d.RunsOn, d.File)
	}
	return fmt.Sprintf("%s: %s (%s)", d.Conn, d.File, humanBytes(d.Bytes))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func runDump(ctx context.Context, connExpr, to string, o dumpOpts) error {
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
	if _, err := os.Stat(to); err == nil {
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick a new file name; backups are never overwritten", "%s already exists", to)
	}
	runsOn := "local"
	if c.Via != "" {
		runsOn = c.Via
	}
	data := transferData{Conn: c.Name, File: to, RunsOn: runsOn, DryRun: g.dryRun}
	rec := map[string]any{"conns": []string{c.Name}, "file": to}

	if t.Kind.File { // sqlite: a consistent copy of the database file
		if o.format == "custom" || o.schemaOnly || len(o.tables) > 0 {
			return out.Usage("sqlite backups copy the whole database file; --format, --schema-only and --table do not apply")
		}
		if strings.HasSuffix(to, ".gz") {
			return out.Usage("sqlite backups are database files; drop the .gz")
		}
		data.Tool = []string{"VACUUM INTO"}
		if g.dryRun {
			out.P.Print("db.dump", data, nil)
			return nil
		}
		err := writeAtomic(to, func(tmp string) error {
			os.Remove(tmp) // VACUUM INTO needs a path that does not exist yet
			db, closeDB, err := openDB(ctx, st, c, true)
			if err != nil {
				return err
			}
			defer closeDB()
			// the connection stays mode=ro; query_only would also block writing the copy
			if _, err := db.ExecContext(ctx, "PRAGMA query_only = 0"); err != nil {
				return out.Errf(out.ExitRemote, "DB_ERROR", "check that the database file is not locked by another program", "%v", err)
			}
			if _, err := db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
				return out.Errf(out.ExitRemote, "DB_ERROR", "the database may be locked or corrupt; try again or check the file", "backup failed: %v", err)
			}
			return nil
		})
		return finishTransfer(st, "db.dump", data, rec, err)
	}

	tool, err := toolsFor(c, t)
	if err != nil {
		return err
	}
	if tool.dump, err = o.args(t.Kind.Name, tool.dump); err != nil {
		return err
	}
	data.Tool = tool.dump
	if g.dryRun {
		out.P.Print("db.dump", data, nil)
		return nil
	}
	err = writeAtomic(to, func(tmp string) error {
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		var w io.Writer = f
		var gz *gzip.Writer
		if strings.HasSuffix(to, ".gz") {
			gz = gzip.NewWriter(f)
			w = gz
		}
		if err := runTool(ctx, st, c, tool, tool.dump, nil, w); err != nil {
			return err
		}
		if gz != nil {
			if err := gz.Close(); err != nil {
				return err
			}
		}
		return f.Sync()
	})
	return finishTransfer(st, "db.dump", data, rec, err)
}

func runRestore(ctx context.Context, connExpr, from string) error {
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
	if t.Kind.File {
		return out.Usage("sqlite backups are database files: stop the app and copy the file back instead")
	}
	tool, err := toolsFor(c, t)
	if err != nil {
		return err
	}
	fi, err := os.Stat(from)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "give the path of a backup made by `komando db dump`")
	}
	runsOn := "local"
	if c.Via != "" {
		runsOn = c.Via
	}
	argv := tool.restore
	custom, err := isPgArchive(from)
	if err != nil {
		return err
	}
	if custom {
		if tool.restoreCustom == nil {
			return out.Usage("%s is a PostgreSQL archive; restore it into a PostgreSQL conn", from)
		}
		argv = tool.restoreCustom // pg_restore: an archive holds no client commands to check
	} else if err := withBackup(from, func(r io.Reader) error { return driver.CheckRestore(t.Kind.Name, r) }); err != nil {
		// check the whole file before sending any of it: a stream cut short
		// would let psql commit what it had received
		return err
	}
	// the file is checked first, so a dry run also says whether it is fine
	if err := guardConns(st, []*store.Conn{c}, driver.Verdict{Risk: driver.RiskDestructive,
		RuleIDs: []string{"db-restore"}, Reasons: []string{driver.RuleReason("db-restore")}}); err != nil {
		return err
	}
	data := transferData{Conn: c.Name, File: from, Bytes: fi.Size(), Tool: argv, RunsOn: runsOn, DryRun: g.dryRun}
	if g.dryRun {
		out.P.Print("db.restore", data, nil)
		return nil
	}
	err = withBackup(from, func(r io.Reader) error { return runTool(ctx, st, c, tool, argv, r, io.Discard) })
	return finishTransfer(st, "db.restore", data, map[string]any{"conns": []string{c.Name}, "file": from}, err)
}

// isPgArchive reports whether path is a pg_dump custom archive ("PGDMP").
func isPgArchive(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, localFileErr("FILE_NOT_FOUND", err, "")
	}
	defer f.Close()
	head := make([]byte, 5)
	n, _ := io.ReadFull(f, head)
	return string(head[:n]) == "PGDMP", nil
}

// withBackup opens a backup file (decompressing .gz) and passes it to fn.
func withBackup(path string, fn func(io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return out.Errf(out.ExitUsage, "BAD_FILE", "the file ends in .gz but is not gzip data", "%v", err)
		}
		defer gz.Close()
		r = gz
	}
	return fn(r)
}

func finishTransfer(st *store.State, name string, data transferData, rec map[string]any, err error) error {
	if err == nil && name == "db.dump" {
		if fi, serr := os.Stat(data.File); serr == nil {
			data.Bytes = fi.Size()
		}
	}
	rec["bytes"] = data.Bytes
	if err != nil {
		rec["error"] = toErr(err).Code
	}
	audit(st, name, nil, "", err == nil, rec)
	if err != nil {
		return err
	}
	out.P.Print(name, data, nil)
	return nil
}

// writeAtomic lets fill write a temp file inside a private (0700) folder
// next to path, then links it into place. A failed transfer never leaves a
// partial file, nobody else can read the file while it is written, and an
// existing path is never replaced, even one created meanwhile.
func writeAtomic(path string, fill func(tmp string) error) error {
	dir, err := os.MkdirTemp(filepath.Dir(path), ".komando-*")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, "data")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := fill(tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick a new file name; existing files are never overwritten", "%s already exists", path)
		}
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder is writable and has free space", "%v", err)
	}
	return nil
}

// runTool runs argv with the conn's password in tool.passwordEnv, on the
// --via host or locally, streaming stdin and stdout.
func runTool(ctx context.Context, st *store.State, c *store.Conn, tool dumpTool, argv []string, stdin io.Reader, stdout io.Writer) error {
	password, err := resolvePassword(c)
	if err != nil {
		return err
	}
	if strings.ContainsAny(password, "\r\n") {
		return out.Errf(out.ExitUsage, "BAD_SECRET", "store the password again without line breaks (`komando secret set NAME`)", "the password for %s contains a line break", c.Name)
	}
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if tool.tls != "" { // the URL asks for TLS: pass it on in this client's own flags
		var version bytes.Buffer
		if err := runTool(ctx, st, c, dumpTool{passwordEnv: tool.passwordEnv, pkg: tool.pkg}, []string{argv[0], "--version"}, nil, &version); err != nil {
			return err
		}
		flags := mysqlTLSFlags(tool.tls, version.String())
		if flags == nil {
			return out.Usage("tls=%s in the conn URL cannot be passed to %s; use true, skip-verify, preferred or false", tool.tls, argv[0])
		}
		argv = append(append([]string{argv[0]}, flags...), argv[1:]...)
	}
	if c.Via == "" {
		if _, err := exec.LookPath(argv[0]); err != nil {
			return out.Errf(out.ExitNotFound, "TOOL_MISSING",
				fmt.Sprintf("install %s on this computer, or reach the database through a server that has it (`komando conn edit %s --via HOST`)", tool.pkg, c.Name),
				"%s is not installed here", argv[0])
		}
		p := exec.CommandContext(ctx, argv[0], argv[1:]...)
		p.Env = append(os.Environ(), tool.passwordEnv+"="+password)
		var stderr strings.Builder
		p.Stdin, p.Stdout, p.Stderr = stdin, stdout, &limitWriter{w: &stderr, n: 64 << 10}
		if err := p.Run(); err != nil {
			return toolErr(ctx, argv[0], "local", strings.TrimSpace(stderr.String()), err)
		}
		return nil
	}
	h, ok := st.Hosts[c.Via]
	if !ok {
		return out.NotFound("host", c.Via)
	}
	sc, err := sshx.Dial(ctx, st, h, sshOpts(st))
	if err != nil {
		return err
	}
	defer sc.Close()
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = sshx.Q(a)
	}
	// the first stdin line is the password; it goes into the tool's
	// environment only, so it never shows up in `ps`
	script := fmt.Sprintf(`command -v %s >/dev/null 2>&1 || { echo "komando: %s is not installed" >&2; exit 127; }
IFS= read -r KOMANDO_PW; %s=$KOMANDO_PW; export %s; unset KOMANDO_PW; exec %s`,
		sshx.Q(argv[0]), argv[0], tool.passwordEnv, tool.passwordEnv, strings.Join(quoted, " "))
	code, stderr, err := sshx.Pipe(ctx, sc, "sh -c "+sshx.Q(script), io.MultiReader(strings.NewReader(password+"\n"), stdin), stdout)
	if err != nil {
		return toolErr(ctx, argv[0], c.Via, strings.TrimSpace(stderr), err)
	}
	if code == 127 {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING",
			fmt.Sprintf("install it on %s: `komando pkg install %s %s`", c.Via, c.Via, tool.pkg),
			"%s is not installed on %s", argv[0], c.Via)
	}
	if code != 0 {
		return toolFailed(argv[0], c.Via, code, stderr, c.Name)
	}
	return nil
}

// toolFailed maps a failed dump or restore tool to the same error codes
// as `db query`: a refused login is DB_AUTH (exit 4), a missing database
// DB_NOT_FOUND (exit 3), anything else TOOL_FAILED.
func toolFailed(tool, where string, code int, stderr, conn string) error {
	msg := fmt.Sprintf("%s failed on %s (exit %d): %s", tool, where, code, lastLines(stderr, 5))
	switch {
	case strings.Contains(stderr, "Access denied"), strings.Contains(stderr, "password authentication failed"),
		strings.Contains(stderr, "no password supplied"):
		return out.Errf(out.ExitConnect, "DB_AUTH", "check the user in the conn URL and its --password-ref (`komando conn show "+conn+"`)", "%s", msg)
	case missingDatabase.MatchString(stderr):
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the database name at the end of the conn URL (`komando conn show "+conn+"`)", "%s", msg)
	}
	return out.Errf(out.ExitRemote, "TOOL_FAILED", toolHint(stderr, conn), "%s", msg)
}

// missingDatabase matches the clients' "no such database" messages (not
// "relation ... does not exist", which is about a table).
var missingDatabase = regexp.MustCompile(`database "[^"]*" does not exist|Unknown database '`)

func toolErr(ctx context.Context, tool, where, stderr string, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for no limit", "%s on %s timed out", tool, where)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return toolFailed(tool, where, ee.ExitCode(), stderr, "NAME")
	}
	return out.Errf(out.ExitError, "TOOL_FAILED", "check that "+tool+" is installed and works: `komando doctor`", "%s on %s: %v", tool, where, err)
}

// toolHint explains the failures people actually hit with dump tools.
func toolHint(stderr, conn string) string {
	switch {
	case strings.Contains(stderr, "server version mismatch"):
		return "pg_dump is older than the server; install a postgresql-client at least as new as the server where the tool runs"
	case strings.Contains(stderr, "unrecognized configuration parameter"):
		return "the backup was made by a newer pg_dump than this server understands; restore it into a server of that version or newer (the restore ran in one transaction, so nothing changed)"
	case strings.Contains(stderr, "already exists"):
		return "the database already has these tables; restore into an empty database, or drop them first (PostgreSQL restores run in one transaction, so nothing changed)"
	case strings.Contains(stderr, "Access denied"), strings.Contains(stderr, "password authentication failed"):
		return "check the user in the conn URL and its --password-ref (`komando conn show " + conn + "`)"
	}
	return "read the message; `komando conn test " + conn + "` checks reachability"
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// limitWriter keeps at most n bytes.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(len(p), l.n)
		l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
