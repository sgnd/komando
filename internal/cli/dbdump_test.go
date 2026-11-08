package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// TestRestorePlainSQLIsBuiltIn: a plain SQL backup is never piped into psql
// or mysql on the --via server (they would obey \! inside it); komando
// runs it itself, and the file is checked first, also in a dry run.
func TestRestorePlainSQLIsBuiltIn(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "bastion", "deploy@10.0.0.1")
	mustRun(t, "conn", "add", "pg", "postgres://app@10.0.0.2/app", "--via", "bastion")
	mustRun(t, "conn", "add", "my", "mysql://app@10.0.0.3:3306/app", "--via", "bastion")
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := write("ok.sql", "CREATE TABLE t (id int);\n")
	for _, conn := range []string{"pg", "my"} {
		d := mustRun(t, "db", "restore", conn, "--from", plain, "--dry-run")
		if tool, _ := d["tool"].([]any); len(tool) != 1 || tool[0] != "komando" {
			t.Errorf("%s: plain SQL restore uses %v, want komando", conn, d["tool"])
		}
		if d["runs_on"] != "local" { // komando runs here, only tunnelling through bastion
			t.Errorf("%s: runs_on %v, want local", conn, d["runs_on"])
		}
	}
	// what the SQL does beyond writing data is named in the stop
	program := write("program.sql", "CREATE TABLE t (id int);\nCOPY t FROM PROGRAM 'id';\n")
	d := mustRun(t, "db", "restore", "pg", "--from", program, "--dry-run")
	blocked := fmt.Sprint(d["_meta"].(map[string]any)["would_be_blocked"])
	if !strings.Contains(blocked, "db-restore,sql-program") || !strings.Contains(blocked, "(line 2)") {
		t.Errorf("COPY ... PROGRAM: would_be_blocked %s, want db-restore,sql-program with its line", blocked)
	}
	hidden := write("bad.sql", "SELECT E'\\'';\n\\! touch /tmp/pwned\nSELECT 1;\n")
	if _, e := invRun(t, "db", "restore", "pg", "--from", hidden, "--dry-run"); e == nil || e.Code != "UNSAFE_BACKUP" {
		t.Errorf("hidden \\! after an E-string: want UNSAFE_BACKUP, got %v", e)
	}
	connect := write("all.sql", "CREATE DATABASE app;\n\\connect app\nSELECT 1;\n")
	if _, e := invRun(t, "db", "restore", "pg", "--from", connect, "--dry-run"); e == nil || e.Code != "RESTORE_UNSUPPORTED" {
		t.Errorf("\\connect: want RESTORE_UNSUPPORTED, got %v", e)
	}
	archive := write("a.dump", "PGDMP rest of a pg_dump archive")
	d = mustRun(t, "db", "restore", "pg", "--from", archive, "--dry-run")
	if tool, _ := d["tool"].([]any); len(tool) == 0 || tool[0] != "pg_restore" {
		t.Errorf("archive restore uses %v, want pg_restore", d["tool"])
	}
}

// TestDumpTableIsNotAnOption: mysqldump reads options even after the
// database name, so a --table value that starts with - would be one
// (--result-file=... writes a file on the --via server).
func TestDumpTableIsNotAnOption(t *testing.T) {
	for _, kind := range []string{"mysql", "postgres"} {
		for _, table := range []string{"--result-file=/home/deploy/.ssh/authorized_keys", "-r/x", "--plugin-dir=/tmp", " "} {
			_, err := dumpOpts{format: "plain", tables: []string{"orders", table}}.args(kind, []string{"tool", "app"})
			if e, ok := err.(*out.Error); !ok || e.Exit != out.ExitUsage {
				t.Errorf("%s --table %q: want a usage error, got %v", kind, table, err)
			}
		}
		argv, err := dumpOpts{format: "plain", tables: []string{"orders", "public.items"}}.args(kind, []string{"tool", "app"})
		if err != nil || len(argv) != 4 {
			t.Errorf("%s: plain tables refused: %v %v", kind, argv, err)
		}
	}
	invHome(t)
	mustRun(t, "conn", "add", "my", "mysql://app@10.0.0.3:3306/app")
	if _, e := invRun(t, "db", "dump", "my", "--to", filepath.Join(t.TempDir(), "x.sql"), "--table=--result-file=/tmp/x", "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("db dump --table=--result-file: want a usage error, got %v", e)
	}
	mustRun(t, "conn", "add", "dash", "mysql://app@10.0.0.3:3306/--result-file=x")
	if _, e := invRun(t, "db", "dump", "dash", "--to", filepath.Join(t.TempDir(), "y.sql"), "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("database name starting with -: want a usage error, got %v", e)
	}
}

// TestDumpOnHost: --on HOST runs pg_dump on that server, whatever the
// conn's own path: the password reaches it on stdin only (never in the
// command), it runs under nice and ionice, and the backup streams back
// into the local file. pg_restore for an archive goes the same way.
func TestDumpOnHost(t *testing.T) {
	invHome(t)
	srv := startFakeServer(t)
	const pw = "s3cret-Pa55"
	t.Setenv("KOMANDO_TEST_PG_PW", pw)
	mustRun(t, "conn", "add", "pg", "postgres://app@10.8.0.5:5432/app?sslmode=require", "--password-ref", "env:KOMANDO_TEST_PG_PW")
	mustRun(t, "conn", "add", "lite", "sqlite:///tmp/x.db")
	dir := t.TempDir()
	run := func(args ...string) (map[string]any, *out.Error) {
		return invRun(t, append([]string{"--host-key-policy", "accept-new"}, args...)...)
	}

	// no server to run pg_dump on: custom is refused, with --on in the hint
	if _, e := run("db", "dump", "pg", "--to", filepath.Join(dir, "a.dump"), "--format", "custom", "--dry-run"); e == nil || !strings.Contains(e.Message, "--on HOST") {
		t.Fatalf("custom without a server: %+v", e)
	}
	d, e := run("db", "dump", "pg", "--to", filepath.Join(dir, "a.dump"), "--format", "custom", "--on", "dev", "--dry-run")
	if e != nil {
		t.Fatal(e)
	}
	tool := fmt.Sprint(d["tool"])
	if d["runs_on"] != "dev" || d["low_priority"] != true || !strings.HasPrefix(tool, "[pg_dump") || !strings.Contains(tool, "--format=custom") || strings.Contains(tool, pw) {
		t.Errorf("dry run: %v", d)
	}
	if len(srv.take()) != 0 {
		t.Error("a dry run connected to the server")
	}
	// only inventory servers: the password goes there
	if _, e := run("db", "dump", "pg", "--to", filepath.Join(dir, "b.dump"), "--format", "custom", "--on", "deploy@127.0.0.1", "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("ad-hoc --on: want a usage error, got %+v", e)
	}
	if _, e := run("db", "dump", "lite", "--to", filepath.Join(dir, "c.db"), "--on", "dev", "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("sqlite --on: want a usage error, got %+v", e)
	}
	if _, e := run("db", "dump", "pg", "--to", filepath.Join(dir, "d.sql"), "--on", "dev", "--table=--file=/tmp/x", "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("--table option: want a usage error, got %+v", e)
	}

	// the real run: the fake server answers with the "dump"
	srv.reply("PGDMP archive bytes")
	to := filepath.Join(dir, "prod.dump")
	if _, e = run("db", "dump", "pg", "--to", to, "--format", "custom", "--on", "dev"); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(to); string(b) != "PGDMP archive bytes" {
		t.Errorf("file holds %q", b)
	}
	if fi, _ := os.Stat(to); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
	ex := srv.take()
	if len(ex) != 1 {
		t.Fatalf("execs: %v", ex)
	}
	if strings.Contains(ex[0].cmd, pw) {
		t.Error("the password is in the command line")
	}
	if !strings.HasPrefix(ex[0].stdin, pw+"\n") {
		t.Errorf("stdin does not start with the password line: %q", ex[0].stdin)
	}
	for _, want := range []string{"PGPASSWORD=$KOMANDO_PW", "nice -n 10", "ionice -c3", "pg_dump", "postgres://app@10.8.0.5:5432/app", "--format=custom", `exec "$@"`} {
		if !strings.Contains(ex[0].cmd, want) {
			t.Errorf("command lacks %q:\n%s", want, ex[0].cmd)
		}
	}

	// restore: an archive goes to pg_restore on --on, behind the same gate
	d, e = run("db", "restore", "pg", "--from", to, "--on", "dev", "--dry-run")
	if e != nil {
		t.Fatal(e)
	}
	if d["runs_on"] != "dev" || !strings.HasPrefix(fmt.Sprint(d["tool"]), "[pg_restore") {
		t.Errorf("restore dry run: %v", d)
	}
	if blocked := fmt.Sprint(d["_meta"].(map[string]any)["would_be_blocked"]); !strings.Contains(blocked, "db-restore") {
		t.Errorf("restore: would_be_blocked %s", blocked)
	}
	if _, e = run("db", "restore", "pg", "--from", to, "--on", "dev"); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Errorf("restore without --allow-dangerous: %+v", e)
	}
	if _, e = run("db", "restore", "pg", "--from", to); e == nil || !strings.Contains(e.Message, "--on HOST") {
		t.Errorf("archive restore without a server: %+v", e)
	}
	srv.reply()
	if _, e = run("db", "restore", "pg", "--from", to, "--on", "dev", "--allow-dangerous"); e != nil {
		t.Fatal(e)
	}
	ex = srv.take()
	if len(ex) != 1 || strings.Contains(ex[0].cmd, pw) || ex[0].stdin != pw+"\nPGDMP archive bytes" {
		t.Fatalf("restore execs: %+v", ex)
	}
	if strings.Contains(ex[0].cmd, "nice") || !strings.Contains(ex[0].cmd, "pg_restore") {
		t.Errorf("restore command:\n%s", ex[0].cmd)
	}
	// plain SQL is never sent to psql: --on does not apply
	plain := filepath.Join(dir, "p.sql")
	_ = os.WriteFile(plain, []byte("SELECT 1;\n"), 0o600)
	if _, e = run("db", "restore", "pg", "--from", plain, "--on", "dev", "--dry-run"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("plain SQL with --on: want a usage error, got %+v", e)
	}
}

func TestToolScriptLowPriority(t *testing.T) {
	s := toolScript([]string{"pg_dump", "--dbname", "postgres://a@h/db"}, "PGPASSWORD", false)
	if strings.Contains(s, "nice") {
		t.Errorf("not low: %s", s)
	}
	s = toolScript([]string{"pg_dump", "--dbname", "postgres://a@h/db"}, "PGPASSWORD", true)
	if strings.Index(s, "nice -n 10") > strings.Index(s, "ionice -c3") || !strings.HasSuffix(s, `exec "$@"`) {
		t.Errorf("low: %s", s)
	}
}
