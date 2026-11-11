package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// csvRun runs komando and returns what it wrote to stdout and the error.
func csvRun(t *testing.T, args ...string) (string, *out.Error) {
	t.Helper()
	root := newRoot()
	root.SetArgs(append([]string{"-o", "json"}, args...))
	root.SilenceErrors, root.SilenceUsage = true, true
	var buf bytes.Buffer
	saved := out.P.W
	out.P.W = &buf
	defer func() { out.P.W = saved }()
	if err := root.Execute(); err != nil {
		return buf.String(), toErr(err)
	}
	return buf.String(), nil
}

// A CSV export takes every row, not the 500 a table shows, and a cut one
// fails instead of looking whole.
func TestDBQueryCSVExportsEveryRow(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	mustRun(t, "db", "query", "lite", "--write", "create table t (id int)")
	const q = "with recursive c(x) as (select 1 union all select x+1 from c where x < 1000) select x from c"
	s, e := csvRun(t, "db", "query", "lite", "--csv", q)
	if e != nil || strings.Count(s, "\n") != 1001 {
		t.Errorf("csv: %v, %d lines", e, strings.Count(s, "\n"))
	}
	s, e = csvRun(t, "db", "query", "lite", "--tsv", "-n", "10", q)
	if e != nil || strings.Count(s, "\n") != 11 {
		t.Errorf("-n 10: %v, %d lines", e, strings.Count(s, "\n"))
	}
	if _, e = csvRun(t, "db", "query", "lite", "--csv", "--max-output", "1024", q); e == nil || e.Code != "OUTPUT_TRUNCATED" {
		t.Errorf("cut by --max-output: %+v", e)
	}
	out.P.Format = "json"
	if d := mustRun(t, "db", "query", "lite", q); d["results"].([]any)[0].(map[string]any)["truncated"] != "rows" {
		t.Errorf("JSON keeps the 500-row default: %v", d["results"])
	}
	if e := wantCode(t, "USAGE", "db", "query", "lite"); !strings.Contains(e.Message, "no SQL") {
		t.Errorf("no SQL: %s", e.Message)
	}
}

// A dry run never creates a missing SQLite file; a real --write run does.
func TestDBQueryDryRunCreatesNoFile(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "new.db")
	mustRun(t, "conn", "add", "ne", "sqlite://"+path)
	invRun(t, "db", "query", "ne", "--write", "--dry-run", "create table z (a)")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a dry run created the file")
	}
	wantCode(t, "DB_CONNECT", "db", "query", "ne", "--write", "--dry-run", "create table z (a)")
	mustRun(t, "db", "query", "ne", "--write", "create table z (a)")
	if d := mustRun(t, "db", "query", "ne", "--write", "--dry-run", "insert into z values (1)"); d["rolled_back"] != true {
		t.Errorf("dry run on an existing file: %v", d)
	}
}

// A file conn needs a full path: a relative one names another file in
// every folder komando runs from.
func TestConnAddRelativeFile(t *testing.T) {
	invHome(t)
	for _, u := range []string{"sqlite:relative.db", "sqlite:./a/b.db"} {
		wantCode(t, "USAGE", "conn", "add", "rel", u)
	}
	mustRun(t, "conn", "add", "abs", "sqlite:///var/lib/app.db")
	mustRun(t, "conn", "add", "home", "sqlite:~/app.db")
}

// `komando db add` saves only a database, `queue add` only a queue, ...
func TestKindAddChecksFamily(t *testing.T) {
	invHome(t)
	for _, c := range [][]string{
		{"db", "redis://127.0.0.1:6379/0", "cache add"},
		{"queue", "postgres://x@127.0.0.1/x", "db add"},
		{"cache", "s3://AKIAEXAMPLE@b/p?region=eu-west-1", "storage add"},
	} {
		if e := wantCode(t, "USAGE", c[0], "add", "x", c[1]); !strings.Contains(e.Hint, c[2]) {
			t.Errorf("%s add %s: hint %q", c[0], c[1], e.Hint)
		}
	}
	mustRun(t, "db", "add", "pg", "postgres://x@127.0.0.1/x")
	mustRun(t, "cache", "add", "rc", "redis://127.0.0.1:6379/0")
}

// The line after db dump names a way back that works: db restore refuses
// SQLite files, so for those it says to copy the file.
func TestDumpRestoreNote(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "lite", "sqlite:///var/lib/app.db")
	mustRun(t, "conn", "add", "pg", "postgres://x@127.0.0.1/x")
	if n := restoreNote("lite", "b.db"); strings.Contains(n, "db restore") || !strings.Contains(n, "/var/lib/app.db") {
		t.Errorf("sqlite: %s", n)
	}
	if n := restoreNote("pg", "b.sql.gz"); !strings.Contains(n, "komando db restore pg --from b.sql.gz") {
		t.Errorf("postgres: %s", n)
	}
}

// db kill on SQLite names itself, and opens no file (a write open would
// create a missing one).
func TestDBKillSQLite(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "none.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+path)
	if e := wantCode(t, "NOT_SUPPORTED", "db", "kill", "lite", "1"); !strings.HasPrefix(e.Message, "db kill ") {
		t.Errorf("message: %s", e.Message)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("db kill created the file")
	}
}
