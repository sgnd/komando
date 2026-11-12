package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// fakePgDump puts a pg_dump on PATH that prints version for --version and
// counts its runs in the returned file.
func fakePgDump(t *testing.T, version string) string {
	t.Helper()
	unixOnly(t, "an sh script plays pg_dump")
	dir := t.TempDir()
	runs := filepath.Join(dir, "runs")
	script := "#!/bin/sh\necho run >> " + runs + "\necho 'pg_dump (PostgreSQL) " + version + " (Debian " + version + "-1)'\n"
	if err := os.WriteFile(filepath.Join(dir, "pg_dump"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return runs
}

// pg_dump checks the server's certificate with sslmode=verify-full against
// ~/.postgresql/root.crt where it runs; libpq 16 and newer get
// sslrootcert=system, the system's CAs, as komando's own connections use.
func TestPgDumpTLSRoots(t *testing.T) {
	invHome(t)
	st := &store.State{}
	tool := dumpTool{passwordEnv: "PGPASSWORD", pkg: "postgresql-client", libpq: true}
	args := func(url string) []string {
		t.Helper()
		got, err := toolTLSArgs(context.Background(), st, &store.Conn{Name: "pg", URL: url}, nil, tool, []string{"pg_dump", "--dbname", url, "--schema-only"})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	runs := fakePgDump(t, "16.4")
	if got := args("postgres://app@db.example.com/app?sslmode=verify-full"); got[2] != "postgres://app@db.example.com/app?sslmode=verify-full&sslrootcert=system" || got[3] != "--schema-only" {
		t.Errorf("libpq 16: %q", got)
	}
	for _, url := range []string{
		"postgres://app@db.example.com/app?sslmode=require",
		"postgres://app@db.example.com/app?sslmode=disable",
		"postgres://app@db.example.com/app?sslmode=verify-ca&sslrootcert=/etc/ssl/db-ca.pem",
		"postgres://app@db.example.com/app?sslmode=verify-full&ca=secret:pg-ca",
	} {
		before, _ := os.ReadFile(runs)
		if got := args(url); got[2] != url {
			t.Errorf("%s: %q", url, got)
		}
		if after, _ := os.ReadFile(runs); len(after) != len(before) {
			t.Errorf("%s: asked pg_dump for its version", url)
		}
	}
	fakePgDump(t, "15.8")
	if got := args("postgres://app@db.example.com/app?sslmode=verify-full"); got[2] != "postgres://app@db.example.com/app?sslmode=verify-full" {
		t.Errorf("libpq 15 reads ~/.postgresql/root.crt: %q", got)
	}

	for v, want := range map[string]int{"pg_dump (PostgreSQL) 16.4 (Ubuntu 16.4-1.pgdg22.04+1)\n": 16, "pg_restore (PostgreSQL) 9.6.24": 9, "nothing": 0} {
		if got := libpqMajor(v); got != want {
			t.Errorf("libpqMajor(%q) = %d", v, got)
		}
	}
	// no CA where it runs: a hint, with the ways out
	stderr := `pg_dump: error: connection to server at "db.example.com" (203.0.113.5), port 5432 failed: root certificate file "/home/deploy/.postgresql/root.crt" does not exist`
	e := toErr(toolFailed("pg_dump", "web1", 1, stderr, &store.Conn{Name: "pg"}, tool))
	if e.Code != "DB_CONNECT" || !strings.Contains(e.Hint, "postgresql-client 16") || !strings.Contains(e.Hint, "~/.postgresql/root.crt") {
		t.Errorf("root.crt missing: %+v", e)
	}
}
