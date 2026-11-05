package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// --write opens a read-write transaction, so on a protected conn it asks
// even for SQL rated read: a function call the classifier does not know
// (lo_unlink, setval, a user function) may still change data.
func TestDBQueryWriteOnProtectedAsks(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+path, "--protected")
	mustRun(t, "db", "query", "lite", "--write", "--yes", "create table t (id int)")
	for _, sql := range []string{"select 1", "select count(*) from t"} {
		wantCode(t, "PROTECTED_TARGET", "db", "query", "lite", "--write", sql)
		mustRun(t, "db", "query", "lite", sql) // without --write it only reads
	}
	mustRun(t, "db", "query", "lite", "--write", "--yes", "select 1")
}

// A dry run that the real run would block runs nothing: its rollback does
// not undo every statement (a killed session, COPY ... PROGRAM, DO).
func TestDBQueryDryRunBlockedRunsNothing(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+path, "--protected")
	mustRun(t, "conn", "add", "open", "sqlite://"+filepath.Join(t.TempDir(), "other.db"))
	mustRun(t, "db", "query", "lite", "--write", "--yes", "create table t (id int)")
	mustRun(t, "db", "query", "open", "--write", "create table t (id int)")
	for _, c := range []struct {
		conn, sql string
		blocked   bool
	}{
		{"lite", "delete from t", true},            // destructive, and protected without --yes
		{"lite", "insert into t values (1)", true}, // protected without --yes
		{"open", "delete from t", true},            // destructive without --allow-dangerous
		{"open", "insert into t values (1)", false},
	} {
		d := mustRun(t, "db", "query", c.conn, "--write", "--dry-run", c.sql)
		meta := d["_meta"].(map[string]any)
		res := d["results"].([]any)[0].(map[string]any)
		skipped, _ := res["skipped"].(string)
		if c.blocked != (meta["would_be_blocked"] != nil) || c.blocked != strings.Contains(skipped, "would be blocked") {
			t.Errorf("%s %q: would_be_blocked %v, skipped %q", c.conn, c.sql, meta["would_be_blocked"], skipped)
		}
		if !c.blocked && d["rolled_back"] != true {
			t.Errorf("%s %q: not rolled back: %v", c.conn, c.sql, d)
		}
	}
}
