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
