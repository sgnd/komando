package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// pgVersionMismatch reads pg_dump's "server version: 14.2; pg_dump version:
// 12.17" (pg_dump refuses a server newer than itself before writing any
// data) and returns both versions.
func pgVersionMismatch(stderr string) (server, client string, ok bool) {
	m := versionMismatch.FindStringSubmatch(stderr)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

var (
	versionMismatch = regexp.MustCompile(`server version: ([0-9][0-9.]*)[^;\n]*; pg_dump version: ([0-9][0-9.]*)`)
	// pg_restore older than the pg_dump that wrote the archive
	archiveVersion = regexp.MustCompile(`unsupported version \([0-9.]+\) in file header`)
	// the clients' "cannot connect" messages (not a refused login)
	toolUnreachable = regexp.MustCompile(`could not connect to server|connection to server at .* failed: (Connection refused|Connection timed out|No route to host|timeout expired)|could not translate host name|Connection refused|Can't connect to (local )?MySQL server|Unknown MySQL server host`)
)

func archiveTooNew(stderr string) bool { return archiveVersion.MatchString(stderr) }

// missingDatabase matches the clients' "no such database" messages (not
// "relation ... does not exist", which is about a table).
var missingDatabase = regexp.MustCompile(`database "[^"]*" does not exist|Unknown database '`)

func toolErr(ctx context.Context, tool, where, stderr string, err error, c *store.Conn, dt dumpTool) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for no limit", "%s on %s timed out", tool, where)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return toolFailed(tool, where, ee.ExitCode(), stderr, c, dt)
	}
	return out.Errf(out.ExitError, "TOOL_FAILED", "check that "+tool+" is installed and works: `komando doctor`", "%s on %s: %v", tool, where, err)
}

// toolHint explains the failures people actually hit with dump tools.
func toolHint(stderr, conn string) string {
	switch {
	case strings.Contains(stderr, "server version mismatch"):
		return "pg_dump is older than the server; install a postgresql-client at least as new as the server where the tool runs, or name a server that has one with --on HOST"
	case strings.Contains(stderr, `"transaction_timeout"`):
		return "PostgreSQL 17 tools set transaction_timeout, which servers older than 17 do not know: restore with the server's own major version of the tools (--on a server with that postgresql-client), or into a server 17 or newer (the restore ran in one transaction, so nothing changed)"
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

// dumpErr names objects the built-in dump cannot write, with what to do.
func dumpErr(err error, c *store.Conn) error {
	var ue *dbx.UnsupportedError
	if errors.As(err, &ue) {
		return out.Errf(out.ExitUsage, "DUMP_UNSUPPORTED",
			"run pg_dump on a server that has it and can reach the database (--on HOST), or dump the other tables with --table",
			"%v", err)
	}
	return out.Errf(out.ExitRemote, "DUMP_FAILED", "check the conn with `komando conn test "+c.Name+"`; with --on HOST, pg_dump or mysqldump on that server runs instead", "%v", err)
}

// sqliteRestoreHint: a SQLite backup is a copy of the database file.
const sqliteRestoreHint = "stop the app, then copy the backup file over the database file (`komando upload` or `komando fs mv` on its server)"

// defaultDumpFile is the file db dump writes without --to:
// DATABASE-<date>.sql.gz (.dump for a custom archive), in this folder.
func defaultDumpFile(conn, format string, now time.Time) string {
	name := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == ' ' || r == '@' || r == '*' {
			return '-'
		}
		return r
	}, conn)
	ext := ".sql.gz"
	if format == "custom" {
		ext = ".dump"
	}
	return name + "-" + now.Format("2006-01-02") + ext
}

// offerBackup asks a person at a terminal whether to save the database as
// it is now before a restore (default yes). Agents and scripts are never
// asked; the help and the dry run tell them to run db dump first.
var offerBackup = func(ctx context.Context, conn string) error {
	if !interactive() {
		return nil
	}
	a, err := readAnswer("Save a copy of "+conn+" as it is now first, so you can go back? [Y/n] ", false)
	if err != nil {
		return err
	}
	if a = strings.ToLower(strings.TrimSpace(a)); a == "n" || a == "no" {
		return nil
	}
	to := defaultDumpFile(conn, "plain", time.Now())
	if _, err := os.Stat(to); err == nil {
		to = strings.TrimSuffix(to, ".sql.gz") + time.Now().Format("-150405") + ".sql.gz"
	}
	if err := runDump(ctx, conn, to, "", dumpOpts{format: "plain"}); err != nil {
		return err
	}
	textNote("Saved %s. To go back later: komando db restore %s --from %s --allow-dangerous", to, argQ(conn), argQ(to))
	return nil
}
