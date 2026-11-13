package cli

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Backups always land on (and restore from) this computer. The database's
// own dump tool (pg_dump, mysqldump) runs on a server: the one named with
// --run-on, else the last server of the database's --via path. The data is streamed
// over SSH, with the password in the tool's environment, and a dump runs at
// low priority (nice, ionice). Without such a server (a direct connection or a
// VPN), or when the --via server lacks the tool, komando dumps itself
// (dbx.Dump). Plain SQL is always restored by komando itself (dbx.Restore),
// through the database's --via path: psql and mysql would obey client commands
// such as \! inside the file, on that server. Only a pg_dump archive goes
// to pg_restore on the server, which runs no client commands.

type dumpTool struct {
	dump          []string
	restoreCustom []string // postgres: pg_restore for --format custom archives
	passwordEnv   string
	pkg           string // Debian/Ubuntu package that provides the tools, for hints
	tls           string // mysql: the URL's tls= setting, mapped to client flags at run time
	libpq         bool   // postgres: libpq reads the URL; toolTLSArgs readies its TLS
}

func toolsFor(c *store.Conn, t driver.Target) (dumpTool, error) {
	switch t.Kind.Name {
	case "postgres":
		// libpq accepts the conn URL as is (it never contains a password)
		return dumpTool{
			dump:          []string{"pg_dump", "--dbname", c.URL},
			restoreCustom: []string{"pg_restore", "--dbname", c.URL, "--single-transaction", "--exit-on-error", "--no-password"},
			passwordEnv:   "PGPASSWORD", pkg: "postgresql-client", libpq: true,
		}, nil
	case "mysql":
		if t.Database == "" {
			return dumpTool{}, out.Usage("the conn URL has no database name; add it (mysql://user@host:3306/NAME) to dump or restore")
		}
		if strings.HasPrefix(t.Database, "-") { // mysqldump would read it as an option
			return dumpTool{}, out.Usage("the conn URL's database name %q starts with -; mysqldump cannot take it", t.Database)
		}
		host, port, _ := net.SplitHostPort(t.Address)
		conn := []string{"--host", host, "--port", port}
		if t.User != "" {
			conn = append(conn, "--user", t.User)
		}
		return dumpTool{
			dump:        append(append([]string{"mysqldump"}, conn...), "--single-transaction", "--routines", "--triggers", "--no-tablespaces", t.Database),
			passwordEnv: "MYSQL_PWD", pkg: "mysql-client",
			tls: t.TLS,
		}, nil
	}
	return dumpTool{}, noDumpTool(t)
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
	for _, t := range o.tables {
		// mysqldump reads options even after the database name: a "table"
		// named --result-file=... would write a file on the --via server
		if strings.HasPrefix(t, "-") || strings.TrimSpace(t) == "" {
			return nil, out.Usage("--table %q is not a table name", t)
		}
	}
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
	var to, on string
	var o dumpOpts
	c := &cobra.Command{
		Use:   "dump CONN",
		Short: "Save a copy of a database to a file on this computer",
		Long: `Saves a copy of the database to a file on this computer. Without --to the
file is CONN-<date>.sql.gz (SQLite: CONN-<date>.db) in this
folder. A file ending in .gz is compressed. Afterwards komando prints the
command that loads it back.

pg_dump or mysqldump runs on a server that has it: the one you name with
--run-on HOST, else the database's --via server. It connects to the conn URL's
address from that server, runs at low priority (nice, ionice) and streams
the backup back over SSH. Without such a server (a direct connection or a VPN)
komando writes plain SQL itself. PostgreSQL can also write its own archive
with --format custom (compressed, restored with pg_restore; needs pg_dump on
a server). --table and --schema-only narrow the dump. SQLite databases are copied
as a database file instead. An existing FILE is never overwritten. The file
holds your data: it is created readable only by you.`,
		Example: `  komando db dump prod-db                  # saves prod-db-<date>.sql.gz here
  komando db dump prod-db --to backups/    # the same name, inside backups/
  komando db dump prod-db --to prod-2026-11-02.sql.gz
  komando db dump prod-db --to prod.dump --format custom
  komando db dump prod-db --to prod.dump --format custom --run-on db1
  komando db dump prod-db --to orders.sql --table public.orders --table public.order_items
  komando db dump prod-db --to schema.sql --schema-only
  komando db dump local --to backup.db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, file := args[0], false
			if st, err := loadState(); err == nil {
				if c, err := singleConn(st, args[0], "db"); err == nil {
					conn = c.Name // the file and the note name the conn, not a selector
					if t, err := driver.Parse(c.URL); err == nil && t.Kind.File {
						file = true
					}
				}
			}
			def := defaultDumpFile(conn, o.format, time.Now())
			if file {
				def = strings.TrimSuffix(def, ".sql.gz") + ".db"
			}
			switch fi, err := os.Stat(to); {
			case to == "-":
				return out.Usage("db dump writes a file on this computer, not to stdout: give --to FILE, or a folder for %s", def)
			case to == "":
				to = def
			case err == nil && fi.IsDir(): // --to backups/: the usual name inside it
				to = filepath.Join(to, def)
			}
			if o.format != "plain" && o.format != "custom" {
				return out.Usage("--format is plain (SQL) or custom (PostgreSQL archive)")
			}
			if o.format == "custom" && strings.HasSuffix(to, ".gz") {
				return out.Usage("a custom archive is already compressed; drop the .gz")
			}
			if err := runDump(cmd.Context(), args[0], to, on, o); err != nil {
				return err
			}
			if !g.dryRun {
				textNote("To load it back: %s", restoreNote(conn, to))
			}
			return nil
		},
	}
	c.Flags().StringVar(&to, "to", "", "file to create on this computer (default: CONN-<date>.sql.gz; SQLite: CONN-<date>.db)")
	c.Flags().StringVar(&o.format, "format", "plain", "plain (SQL) or custom (PostgreSQL archive for pg_restore)")
	c.Flags().BoolVar(&o.schemaOnly, "schema-only", false, "tables, indexes and functions, no rows")
	c.Flags().StringArrayVar(&o.tables, "table", nil, "only this table (repeatable; SCHEMA.TABLE on PostgreSQL)")
	c.Flags().StringVar(&on, "run-on", "", "run pg_dump or mysqldump on this server (default: the database's --via server)")
	return c
}

func dbRestoreCmd() *cobra.Command {
	var from, on string
	c := &cobra.Command{
		Use:   "restore CONN --from FILE",
		Short: "Load a backup into a database",
		Long: `Runs the SQL in FILE (from ` + "`db dump`" + `, pg_dump, mysqldump or any plain SQL
file; .gz is read compressed). komando runs the SQL itself, through the
conn's --via path, never with psql or mysql. A PostgreSQL archive
(` + "`db dump --format custom`" + `) is recognized by its content and loaded with
pg_restore on a server: the one named with --run-on HOST, else the database's --via
server; the archive is streamed to it over SSH.

In a terminal komando first offers to save a copy of the database as it is
now (db dump), so you can go back. Scripts and AI agents get no question: run
` + "`komando db dump CONN`" + ` yourself first.

A restore can overwrite existing data, so it needs --allow-dangerous, plus
--yes on a protected database. The whole file is checked first: client commands
that could run programs (\! or system) and SQL komando cannot follow (a file
ending inside a quote, a change to how quotes are read) are refused, and SQL
that runs programs, touches server files or changes privileges is named in
the approval.

PostgreSQL restores run in one transaction: on any error nothing changes.
MySQL runs the statements in order and stops at the first error.`,
		Example: `  komando db restore staging-db --from prod-2026-11-02.sql.gz --dry-run   # checks the file, changes nothing
  komando db restore staging-db --from prod-2026-11-02.sql.gz --allow-dangerous
  komando db restore staging-db --from prod.dump --run-on db1 --allow-dangerous`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return out.Usage("give the backup to load with --from FILE").
					WithHint("for example: komando db restore " + argQ(args[0]) + " --from backup.sql.gz --dry-run (`komando db dump` makes the file)")
			}
			return runRestore(cmd.Context(), args[0], from, on)
		},
	}
	c.Flags().StringVar(&from, "from", "", "SQL file on this computer")
	c.Flags().StringVar(&on, "run-on", "", "run pg_restore for a PostgreSQL archive on this server (default: the database's --via server)")
	return c
}

type transferData struct {
	Conn        string   `json:"conn"`
	File        string   `json:"file"`
	Bytes       int64    `json:"bytes"`
	Tool        []string `json:"tool,omitempty"`
	RunsOn      string   `json:"runs_on"`                // "local", or the server that runs the tool
	LowPriority bool     `json:"low_priority,omitempty"` // the tool runs under nice and ionice
	DryRun      bool     `json:"dry_run,omitempty"`
}

func (d transferData) Text() string {
	if d.DryRun {
		low := ""
		if d.LowPriority {
			low = " at low priority"
		}
		return fmt.Sprintf("dry run: would run %s on %s%s for %s", strings.Join(d.Tool, " "), d.RunsOn, low, d.File)
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

func runDump(ctx context.Context, connExpr, to, on string, o dumpOpts) error {
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
	data := transferData{Conn: c.Name, File: to, RunsOn: "local", DryRun: g.dryRun}
	rec := map[string]any{"conns": []string{c.Name}, "file": to}

	if t.Kind.File { // sqlite: a consistent copy of the database file
		if o.format == "custom" || o.schemaOnly || len(o.tables) > 0 || on != "" {
			return out.Errf(out.ExitUsage, "USAGE", "drop those flags: komando db dump "+argQ(c.Name)+" --to backup.db", "sqlite backups copy the whole database file; --format, --schema-only, --table and --run-on do not apply")
		}
		if strings.HasSuffix(to, ".gz") {
			return out.Errf(out.ExitUsage, "USAGE", "for example: komando db dump "+argQ(c.Name)+" --to backup.db", "sqlite backups are database files; drop the .gz")
		}
		data.Tool = []string{"VACUUM INTO"}
		rec["runs_on"] = "local"
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
				return out.Errf(out.ExitRemote, "DB_ERROR", "the database may be locked or corrupt; run it again or check the file", "backup failed: %v", err)
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
	h, err := toolHost(st, c, on)
	if err != nil {
		return err
	}
	builtin := h == nil
	if builtin && o.format == "custom" {
		return out.Usage("--format custom is pg_dump's archive; it needs pg_dump on a server: add --run-on HOST (a server with pg_dump that can reach the database). komando's own dump writes plain SQL")
	}
	data.Tool = tool.dump
	if builtin { // komando dumps here, through the --via path if there is one
		data.Tool = []string{"komando"}
	} else {
		data.RunsOn, data.LowPriority = h.Name, true
	}
	rec["runs_on"] = data.RunsOn
	if g.dryRun {
		out.P.Print("db.dump", data, nil)
		return nil
	}
	builtinDump := func(w io.Writer) error {
		db, closeDB, err := openDB(ctx, st, c, true)
		if err != nil {
			return err
		}
		defer closeDB()
		if err := dbx.Dump(ctx, db, t.Kind.Name, dbx.DumpOptions{SchemaOnly: o.schemaOnly, Tables: o.tables}, w); err != nil {
			return dumpErr(err, c)
		}
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
		if builtin {
			if err := builtinDump(w); err != nil {
				return err
			}
		} else if err := runTool(ctx, st, c, h, tool, tool.dump, nil, w, true); err != nil {
			code := toErr(err).Code
			if (code != "TOOL_MISSING" && code != "TOOL_TOO_OLD") || o.format == "custom" || on != "" {
				return err
			}
			// the --via server has no usable pg_dump/mysqldump: komando
			// dumps it itself (a server named with --run-on is never skipped)
			data.Tool, data.RunsOn, data.LowPriority = []string{"komando"}, "local", false
			rec["runs_on"] = "local"
			if _, err := f.Seek(0, 0); err != nil {
				return err
			}
			if err := f.Truncate(0); err != nil {
				return err
			}
			if gz != nil {
				gz.Reset(f)
			}
			if err := builtinDump(w); err != nil {
				return err
			}
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

func runRestore(ctx context.Context, connExpr, from, on string) error {
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
		return out.Errf(out.ExitUsage, "USAGE", sqliteRestoreHint, "sqlite backups are database files: komando does not restore them; copy the file back instead")
	}
	h, err := toolHost(st, c, on)
	if err != nil {
		return err
	}
	tool, err := toolsFor(c, t)
	if err != nil {
		return err
	}
	fi, err := os.Stat(from)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "give the path of a backup made by `komando db dump`")
	}
	var argv []string
	custom, err := isPgArchive(from)
	if err != nil {
		return err
	}
	if custom {
		if tool.restoreCustom == nil {
			return out.Usage("%s is a PostgreSQL archive; restore it into a PostgreSQL database", from)
		}
		argv = tool.restoreCustom // pg_restore: an archive holds no client commands to check
	}
	v := driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"db-restore"}, Reasons: []string{driver.RuleReason("db-restore")}}
	if !custom {
		if err := checkRestoreSQL(t.Kind.Name, from, &v); err != nil {
			return err
		}
	}
	if !custom && on != "" {
		return out.Usage("%s is plain SQL, which komando always restores itself (psql and mysql would obey client commands in it); --run-on is only for pg_dump archives", from)
	}
	if custom && h == nil {
		return out.Usage("%s is a pg_dump archive; restoring it needs pg_restore on a server: add --run-on HOST (a server with pg_restore that can reach the database). komando restores plain SQL itself", from)
	}
	// the file is checked first, so a dry run also says whether it is fine
	if err := guardConns(st, []*store.Conn{c}, v); err != nil {
		return err
	}
	// plain SQL is always run by komando itself: psql and mysql would obey
	// client commands hidden in the file, on the --via server
	builtin := !custom
	data := transferData{Conn: c.Name, File: from, Bytes: fi.Size(), Tool: argv, DryRun: g.dryRun}
	if builtin {
		// komando runs here; only the connection goes through the --via path
		data.Tool, data.RunsOn = []string{"komando"}, "local"
	} else {
		data.RunsOn = h.Name
	}
	if g.dryRun {
		out.P.Print("db.restore", data, nil)
		textNote("To keep a way back, save a copy first: komando db dump %s", argQ(c.Name))
		return nil
	}
	if err := offerBackup(ctx, c.Name); err != nil {
		return err
	}
	builtinRestore := func() error {
		db, closeDB, err := openDB(ctx, st, c, false)
		if err != nil {
			return err
		}
		defer closeDB()
		return withBackup(from, func(r io.Reader) error {
			if err := dbx.Restore(ctx, db, t.Kind.Name, r); err != nil {
				// what the database holds now depends on the engine (S-8.4):
				// PostgreSQL restores in one transaction, MySQL cannot
				state := "nothing was changed (PostgreSQL restores in one transaction)"
				if t.Kind.Name == "mysql" {
					state = "the statements before that line were applied (MySQL cannot roll back tables)"
				}
				return out.Errf(out.ExitRemote, "RESTORE_FAILED", "fix the file, then restore it again: `komando db restore "+c.Name+" --from "+from+"`",
					"%v; %s", err, state)
			}
			return nil
		})
	}
	if builtin {
		err = builtinRestore()
	} else {
		err = withBackup(from, func(r io.Reader) error { return runTool(ctx, st, c, h, tool, argv, r, io.Discard, false) })
	}
	return finishTransfer(st, "db.restore", data, map[string]any{"conns": []string{c.Name}, "file": from, "runs_on": data.RunsOn}, err)
}

// checkRestoreSQL checks the whole file before sending any of it: what the
// SQL does beyond writing data (COPY ... PROGRAM, INTO OUTFILE, GRANT, ...)
// is added to v, so it is named in the approval and in POLICY_BLOCKED.
func checkRestoreSQL(kind, from string, v *driver.Verdict) error {
	var sqlV driver.Verdict
	if err := withBackup(from, func(r io.Reader) (err error) {
		sqlV, err = driver.CheckRestore(kind, r)
		return err
	}); err != nil {
		return err
	}
	v.RuleIDs = append(v.RuleIDs, sqlV.RuleIDs...)
	v.Reasons = append(v.Reasons, sqlV.Reasons...)
	return nil
}

// isPgArchive reports whether path is a pg_dump custom archive ("PGDMP").
func isPgArchive(path string) (bool, error) {
	if err := guardLocalRead(path); err != nil {
		return false, err
	}
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
	if err := guardLocalRead(path); err != nil {
		return err
	}
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
// server h (see toolHost) or, when h is nil, here, streaming stdin and
// stdout. low runs it under nice and ionice on the server.
func runTool(ctx context.Context, st *store.State, c *store.Conn, h *store.Host, tool dumpTool, argv []string, stdin io.Reader, stdout io.Writer, low bool) error {
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
	tool, argv, ca, err := toolWithCA(c, h, tool, argv) // the conn's ?ca= certificate, in a file for the tool (db_dump_ca.go)
	if err != nil {
		return err
	}
	defer ca.remove()
	// after toolWithCA: a URL with its own CA file gets no sslrootcert=system
	if argv, err = toolTLSArgs(ctx, st, c, h, tool, argv); err != nil {
		return err
	}
	if h == nil {
		if _, err := exec.LookPath(argv[0]); err != nil {
			return out.Errf(out.ExitNotFound, "TOOL_MISSING",
				fmt.Sprintf("install %s on this computer, or run it on a server that has it (--run-on HOST)", tool.pkg),
				"%s is not installed here", argv[0])
		}
		p := exec.CommandContext(ctx, argv[0], argv[1:]...)
		p.Env = append(os.Environ(), tool.passwordEnv+"="+password)
		var stderr strings.Builder
		p.Stdin, p.Stdout, p.Stderr = stdin, stdout, &limitWriter{w: &stderr, n: 64 << 10}
		if err := p.Run(); err != nil {
			return toolErr(ctx, argv[0], "local", strings.TrimSpace(stderr.String()), err, c, tool)
		}
		return nil
	}
	// komando reaches the server through its own --via path
	if h.Windows() {
		return notOnWindows("running the dump tool --run-on a server", []string{h.Name})
	}
	sc, err := sshx.Dial(ctx, st, h, sshOpts(st))
	if err != nil {
		return err
	}
	defer sc.Close()
	caDir, caLines := ca.onServer()
	code, stderr, err := sshx.Pipe(ctx, sc, "sh -c "+sshx.Q(toolScript(argv, tool.passwordEnv, caDir, low)), io.MultiReader(strings.NewReader(password+"\n"+caLines), stdin), stdout)
	if err != nil {
		return toolErr(ctx, argv[0], h.Name, strings.TrimSpace(stderr), err, c, tool)
	}
	if code == 127 {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING",
			fmt.Sprintf("install it on %s (`komando pkg install %s %s`), or name a server that has it with --run-on HOST", h.Name, h.Name, tool.pkg),
			"%s is not installed on %s", argv[0], h.Name)
	}
	if code != 0 {
		return toolFailed(argv[0], h.Name, code, stderr, c, tool)
	}
	return nil
}

// toolHost picks the server that runs the dump tool: the one named with
// --run-on, else the last server of the database's --via path (the path before it
// is how komando reaches that server). nil means none: a direct conn, or
// one reached through a VPN.
func toolHost(st *store.State, c *store.Conn, on string) (*store.Host, error) {
	if on != "" {
		h, err := singleHost(st, on)
		if err != nil {
			return nil, err
		}
		// the conn's password goes to this server: only one from the inventory
		if st.Hosts[h.Name] != h {
			return nil, out.Errf(out.ExitUsage, "USAGE", "add the server first (`komando host add NAME USER@ADDRESS`), then use --run-on NAME",
				"--run-on takes a server from your list, not %q", on)
		}
		return h, runOnSecret(st, c, h)
	}
	if c.Via == "" {
		return nil, nil
	}
	h, vpn, err := resolveVia(st, c.Via)
	if err != nil {
		return nil, err
	}
	if vpn != nil {
		return nil, nil
	}
	return h, nil
}

// runOnSecret: a server named with --run-on that is not the conn's own
// --via server gets the conn's password, so for an AI agent it needs a
// person's yes (SECRET_DESTINATION), as any other place a secret goes.
func runOnSecret(st *store.State, c *store.Conn, h *store.Host) error {
	if c.PasswordRef == "" {
		return nil
	}
	if c.Via != "" {
		if own, vpn, err := resolveVia(st, c.Via); err == nil && vpn == nil && own != nil && own.Name == h.Name {
			return nil
		}
	}
	return guardSecretUse([]string{c.PasswordRef}, h.Name+" (--run-on: the dump tool for conn "+c.Name+" runs there)")
}

// toolFailed maps a failed dump or restore tool to the same error codes
// as `db query`: a refused login is DB_AUTH (exit 4), a missing database
// DB_NOT_FOUND (exit 3), a database the tool cannot reach from where it
// runs CONN_UNREACHABLE (exit 4), a tool older than the server or archive
// TOOL_TOO_OLD, anything else TOOL_FAILED.
func toolFailed(tool, where string, code int, stderr string, c *store.Conn, dt dumpTool) error {
	conn := c.Name
	msg := fmt.Sprintf("%s failed on %s (exit %d): %s", tool, where, code, lastLines(stderr, 5))
	if server, client, ok := pgVersionMismatch(stderr); ok {
		major := strings.SplitN(server, ".", 2)[0]
		hint := fmt.Sprintf("pg_dump %s is older than the server (%s): install postgresql-client-%s where the tool runs, or name a server that has it with --run-on HOST", client, server, major)
		if where != "local" {
			hint = fmt.Sprintf("pg_dump %s on %s is older than the server (%s): install postgresql-client-%s there (`komando pkg install %s postgresql-client-%s`; Debian and Ubuntu may need the PostgreSQL apt repository), or name another server with --run-on HOST", client, where, server, major, where, major)
		}
		return out.Errf(out.ExitRemote, "TOOL_TOO_OLD", hint, "%s", msg)
	}
	if h := rootCertHint(stderr, tool, where); h != "" {
		return out.Errf(out.ExitConnect, "DB_CONNECT", h, "%s", msg)
	}
	if archiveTooNew(stderr) {
		return out.Errf(out.ExitRemote, "TOOL_TOO_OLD",
			"the archive was made by a newer pg_dump than "+tool+" on "+where+" reads: install a newer "+dt.pkg+" there, or name a server that has one with --run-on HOST (nothing was changed)",
			"%s", msg)
	}
	switch {
	case strings.Contains(stderr, "Access denied"), strings.Contains(stderr, "password authentication failed"),
		strings.Contains(stderr, "no password supplied"):
		return out.Errf(out.ExitConnect, "DB_AUTH", "check the user in the conn URL and its --password-ref (`komando conn show "+conn+"`)", "%s", msg)
	case missingDatabase.MatchString(stderr):
		return out.Errf(out.ExitNotFound, "DB_NOT_FOUND", "check the database name at the end of the conn URL (`komando conn show "+conn+"`)", "%s", msg)
	}
	if toolUnreachable.MatchString(stderr) {
		return out.Errf(out.ExitConnect, "CONN_UNREACHABLE", unreachableHint(tool, where, c), "%s", msg)
	}
	return out.Errf(out.ExitRemote, "TOOL_FAILED", toolHint(stderr, conn), "%s", msg)
}

// unreachableHint explains that the tool connects to the conn URL's address
// from the server it runs on, and how to point it at a database that
// listens only on that server's 127.0.0.1: a conn with that URL, reached
// through the server.
func unreachableHint(tool, where string, c *store.Conn) string {
	if where == "local" {
		return "check the conn with `komando test " + c.Name + "`"
	}
	addr, local := "the conn URL's address", "URL-WITH-127.0.0.1"
	if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
		addr = u.Host
		cp := *u
		cp.Host = "127.0.0.1"
		if p := u.Port(); p != "" {
			cp.Host += ":" + p
		}
		local = cp.String()
	}
	return fmt.Sprintf("%s runs on %s and connects to %s from there. If the database listens only on 127.0.0.1 on %s, add a conn for that address reached through it (`komando conn add %s-local %s --via %s --password-ref ...`) and dump that conn; otherwise name a server that can reach %s with --run-on HOST",
		tool, where, addr, where, c.Name, local, where, addr)
}
