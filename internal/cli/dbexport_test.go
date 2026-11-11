package cli

import (
	"bytes"
	"errors"
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
		var ec exitCode
		if errors.As(err, &ec) {
			return buf.String(), &out.Error{Code: "EXIT", Exit: int(ec)}
		}
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
	// the error goes to stderr, so stdout stays CSV only
	if s, e = csvRun(t, "db", "query", "lite", "--csv", "--max-output", "1024", q); e == nil || e.Exit != out.ExitError || strings.Contains(s, "{") {
		t.Errorf("cut by --max-output: %+v\n%s", e, s)
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
		if e := wantCode(t, "USAGE", "conn", "add", "rel", u); !strings.Contains(e.Hint, "sqlite:///") {
			t.Errorf("%s: hint %q", u, e.Hint)
		}
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
		if e := wantCode(t, "WRONG_KIND", c[0], "add", "x", c[1]); !strings.Contains(e.Hint, c[2]) {
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

// --expires takes days like --ttl and --older-than.
func TestStorageLinkExpiresDays(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "s3l", "s3://AKIAEXAMPLE@b?region=eu-west-1&endpoint=http://127.0.0.1:9")
	defer func() { g.dryRun = false }()
	mustRun(t, "storage", "link", "s3l", "a.txt", "--expires", "7d", "--dry-run")
	if e := wantCode(t, "USAGE", "storage", "link", "s3l", "a.txt", "--expires", "8d", "--dry-run"); !strings.Contains(e.Message, "7d") {
		t.Errorf("8d: %s", e.Message)
	}
	if e := wantCode(t, "USAGE", "storage", "link", "s3l", "a.txt", "--expires", "30x"); !strings.Contains(e.Message, "--expires") {
		t.Errorf("30x: %s", e.Message)
	}
}

// A bad URL of one kind gets that kind's example, not another kind's.
func TestConnAddKindExample(t *testing.T) {
	invHome(t)
	if e := wantCode(t, "USAGE", "queue", "add", "ps", "pubsub://proj"); !strings.Contains(e.Hint, "pubsub://my-project") {
		t.Errorf("hint: %s", e.Hint)
	}
}

// db commands stop a query after 30s, not the global 5m; their help says so.
func TestDBHelpTimeout(t *testing.T) {
	root := newRoot()
	for _, path := range [][]string{{"db", "query"}, {"db", "user", "ls"}, {"db", "dump"}} {
		c, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		c.SetOut(&b)
		_ = c.Help()
		want := map[bool]string{true: "default 30s", false: "default: setting, 5m"}[path[1] != "dump"]
		if !strings.Contains(b.String(), want) {
			t.Errorf("%v help: no %q in\n%s", path, want, b.String())
		}
	}
}

// An SQS emulator at localhost needs no AWS login: komando does not wait
// for EC2 metadata, and fails on the closed port instead.
func TestSQSEmulatorNoLogin(t *testing.T) {
	invHome(t)
	t.Setenv("AWS_CONFIG_FILE", os.DevNull)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", os.DevNull)
	mustRun(t, "conn", "add", "sq", "sqs://eu-west-1?endpoint=http://127.0.0.1:9")
	_, e := invRun(t, "queue", "ls", "sq")
	if e == nil || strings.HasPrefix(e.Code, "AWS_") {
		t.Errorf("want a connect error, got %+v", e)
	}
	if !loopback("[::1]:4566") || !loopback("localhost:4566") || loopback("10.0.0.1:4566") {
		t.Error("loopback")
	}
}
