package cli

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	passwordEnv   string
	pkg           string // Debian/Ubuntu package that provides the tools, for hints
}

func toolsFor(c *store.Conn, t driver.Target) (dumpTool, error) {
	switch t.Kind.Name {
	case "postgres":
		// libpq accepts the conn URL as is (it never contains a password)
		return dumpTool{
			dump:        []string{"pg_dump", "--dbname", c.URL},
			restore:     []string{"psql", "--dbname", c.URL, "--single-transaction", "--set", "ON_ERROR_STOP=1", "--quiet", "--no-psqlrc"},
			passwordEnv: "PGPASSWORD", pkg: "postgresql-client",
		}, nil
	case "mysql":
		host, port, _ := net.SplitHostPort(t.Address)
		conn := []string{"--host", host, "--port", port}
		if t.User != "" {
			conn = append(conn, "--user", t.User)
		}
		return dumpTool{
			dump:        append(append([]string{"mysqldump"}, conn...), "--single-transaction", "--routines", "--triggers", "--no-tablespaces", t.Database),
			restore:     append(append([]string{"mysql"}, conn...), t.Database),
			passwordEnv: "MYSQL_PWD", pkg: "mysql-client",
		}, nil
	}
	return dumpTool{}, out.Usage("%s conns have no dump tool", t.Kind.Name)
}

func dbDumpCmd() *cobra.Command {
	var to string
	c := &cobra.Command{
		Use:   "dump CONN --to FILE",
		Short: "Back up a database to a file on this computer (.gz to compress)",
		Long: `Runs pg_dump or mysqldump (on the conn's --via host when set, otherwise here)
and saves plain SQL to FILE on this computer. FILE ending in .gz is compressed.
SQLite conns are copied as a database file instead. An existing FILE is never
overwritten. The file holds your data: it is created readable only by you.`,
		Example: `  komando db dump prod-db --to prod-2026-11-02.sql.gz
  komando db dump local --to backup.db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return out.Usage("--to FILE is required")
			}
			return runDump(cmd.Context(), args[0], to)
		},
	}
	c.Flags().StringVar(&to, "to", "", "file to create on this computer")
	return c
}

func dbRestoreCmd() *cobra.Command {
	var from string
	var write bool
	c := &cobra.Command{
		Use:   "restore CONN --from FILE",
		Short: "Load a SQL backup into a database (needs --write and --allow-dangerous)",
		Long: `Runs the SQL in FILE (from ` + "`db dump`" + ` or any plain SQL file; .gz is read
compressed) with psql or mysql. A restore can overwrite existing data, so it
needs --write and --allow-dangerous, plus --yes on a protected conn.
PostgreSQL restores run in one transaction: on any error nothing changes.`,
		Example: `  komando db restore staging-db --from prod-2026-11-02.sql.gz --write --allow-dangerous`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return out.Usage("--from FILE is required")
			}
			return runRestore(cmd.Context(), args[0], from, write)
		},
	}
	c.Flags().StringVar(&from, "from", "", "SQL file on this computer")
	c.Flags().BoolVar(&write, "write", false, "confirm that the restore changes the database")
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

func runDump(ctx context.Context, connExpr, to string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "sql")
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
				return out.Errf(out.ExitRemote, "DB_ERROR", "", "%v", err)
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

func runRestore(ctx context.Context, connExpr, from string, write bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	c, err := singleConn(st, connExpr, "sql")
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
		return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "cannot read %s: %v", from, err)
	}
	if !write {
		return out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG", "a restore changes the database; add --write (and --allow-dangerous, since it can overwrite data)", "restore needs --write")
	}
	if err := guardConns([]*store.Conn{c}, driver.Verdict{Risk: driver.RiskDestructive,
		RuleIDs: []string{"db-restore"}, Reasons: []string{driver.RuleReason("db-restore")}}); err != nil {
		return err
	}
	runsOn := "local"
	if c.Via != "" {
		runsOn = c.Via
	}
	data := transferData{Conn: c.Name, File: from, Bytes: fi.Size(), Tool: tool.restore, RunsOn: runsOn, DryRun: g.dryRun}
	if g.dryRun {
		out.P.Print("db.restore", data, nil)
		return nil
	}
	f, err := os.Open(from)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(from, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return out.Errf(out.ExitUsage, "BAD_FILE", "the file ends in .gz but is not gzip data", "%v", err)
		}
		defer gz.Close()
		r = gz
	}
	err = runTool(ctx, st, c, tool, tool.restore, r, io.Discard)
	return finishTransfer(st, "db.restore", data, map[string]any{"conns": []string{c.Name}, "file": from}, err)
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

// writeAtomic lets fill write a temp file next to path (mode 0600), then
// renames it into place, so a failed backup never leaves a partial file.
func writeAtomic(path string, fill func(tmp string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".komando-*.tmp")
	if err != nil {
		return out.Errf(out.ExitError, "FILE_ERROR", "check that the folder exists and is writable", "%v", err)
	}
	tmp := f.Name()
	f.Close()
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := fill(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
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
	if g.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	if stdin == nil {
		stdin = strings.NewReader("")
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
		return out.Errf(out.ExitRemote, "TOOL_FAILED", "read the message; `komando conn test "+c.Name+"` checks reachability", "%s failed on %s (exit %d): %s", argv[0], c.Via, code, lastLines(stderr, 5))
	}
	return nil
}

func toolErr(ctx context.Context, tool, where, stderr string, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for no limit", "%s on %s timed out", tool, where)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.Errf(out.ExitRemote, "TOOL_FAILED", "read the message; `komando conn test NAME` checks reachability", "%s failed on %s (exit %d): %s", tool, where, ee.ExitCode(), lastLines(stderr, 5))
	}
	return out.Errf(out.ExitError, "TOOL_FAILED", "", "%s on %s: %v", tool, where, err)
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
