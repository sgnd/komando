package cli

import (
	"path/filepath"
	"slices"
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
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "--yes", "create table t (id int)")
	for _, sql := range []string{"select 1", "select count(*) from t"} {
		wantCode(t, "PROTECTED_TARGET", "database", "sqlite", "query", "lite", "--write", sql)
		mustRun(t, "database", "sqlite", "query", "lite", sql) // without --write it only reads
	}
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "--yes", "select 1")
}

// A dry run that the real run would block runs nothing: its rollback does
// not undo every statement (a killed session, COPY ... PROGRAM, DO).
func TestDBQueryDryRunBlockedRunsNothing(t *testing.T) {
	invHome(t)
	path := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "lite", "sqlite://"+path, "--protected")
	mustRun(t, "conn", "add", "open", "sqlite://"+filepath.Join(t.TempDir(), "other.db"))
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "--yes", "create table t (id int)")
	mustRun(t, "database", "sqlite", "query", "open", "--write", "create table t (id int)")
	for _, c := range []struct {
		conn, sql string
		blocked   bool
	}{
		{"lite", "delete from t", true},            // destructive, and protected without --yes
		{"lite", "insert into t values (1)", true}, // protected without --yes
		{"open", "delete from t", true},            // destructive without --allow-dangerous
		{"open", "insert into t values (1)", false},
	} {
		d := mustRun(t, "database", "sqlite", "query", c.conn, "--write", "--dry-run", c.sql)
		meta := d["_meta"].(map[string]any)
		res := d["results"].([]any)[0].(map[string]any)
		skipped, _ := res["skipped"].(string)
		if c.blocked != (meta["would_be_blocked"] != nil) || c.blocked != strings.Contains(skipped, "would stop at a safety check") {
			t.Errorf("%s %q: would_be_blocked %v, skipped %q", c.conn, c.sql, meta["would_be_blocked"], skipped)
		}
		if !c.blocked && d["rolled_back"] != true {
			t.Errorf("%s %q: not rolled back: %v", c.conn, c.sql, d)
		}
	}
}

// userStatements are what db grant, db revoke, db user add, db user passwd
// and db user rm sent, written as the SQL (or the Mongo command) a person
// or an agent now gives to `database KIND query`.
var userStatements = []struct{ kind, url, privilege, dropUser string }{
	{"postgres", "postgres://app@127.0.0.1:1/app", "GRANT pg_read_all_data TO app_ro", "DROP USER bob"},
	{"mysql", "mysql://app@127.0.0.1:1/app", "GRANT SELECT ON app.* TO 'bob'@'%'", "DROP USER 'bob'@'%'"},
	{"sqlserver", "sqlserver://app@127.0.0.1:1/app", "GRANT SELECT TO bob", "DROP LOGIN bob"},
	{"oracle", "oracle://app@127.0.0.1:1/ORCL", "GRANT CREATE SESSION TO bob", "DROP USER bob"},
	{"clickhouse", "clickhouse://app@127.0.0.1:1/app", "GRANT SELECT ON app.* TO bob", "DROP USER bob"},
	{"snowflake", "snowflake://app@acct/db", "GRANT ROLE r TO USER bob", "DROP USER bob"},
	{"bigquery", "bigquery://my-project/shop", "GRANT `roles/bigquery.dataViewer` ON SCHEMA shop TO 'user:bob@example.test'", "DROP SCHEMA shop"},
	{"mongodb", "mongodb://app@127.0.0.1:1/shop", `{"grantRolesToUser": "bob", "roles": ["read"]}`, `{"dropUser": "bob"}`},
}

// A statement that changes users or rights, or drops a user, is stopped
// for every database family until an agent says --allow-dangerous; on a
// protected conn --allow-dangerous is not enough, it needs --yes too. The
// conns answer nothing: a run that got past the guard fails to connect.
func TestQueryUserStatementsNeedApproval(t *testing.T) {
	invHome(t)
	noAgent(t)
	for _, c := range userStatements {
		name := "c-" + c.kind
		mustRun(t, "conn", "add", name, c.url, "--protected")
		for _, text := range []string{c.privilege, c.dropUser} {
			args := func(extra ...string) []string {
				return slices.Concat([]string{"database", c.kind, "query", name, "--write"}, extra, []string{text})
			}
			wantCode(t, "POLICY_BLOCKED", args()...)
			wantCode(t, "PROTECTED_TARGET", args("--allow-dangerous")...)
			if c.kind == "mongodb" {
				continue // its connect attempt waits for server selection
			}
			if _, e := invRun(t, args("--allow-dangerous", "--yes")...); e == nil || e.Code == "POLICY_BLOCKED" || e.Code == "PROTECTED_TARGET" {
				t.Errorf("%s %q with --allow-dangerous --yes: want the run to start and fail later, got %+v", c.kind, text, e)
			}
		}
	}
}

// An AI agent's --allow-dangerous opens the window, which names the rule.
func TestQueryPrivilegeStatementAsksForAnAgent(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "local", "postgres://app@127.0.0.1:1/app")
	texts := windowText(t, false)
	_, e := invRun(t, "database", "postgres", "query", "local", "--write", "--allow-dangerous", "GRANT readers TO app_ro")
	if e == nil || len(*texts) != 1 || !strings.Contains((*texts)[0], "sql-privileges") {
		t.Errorf("want one window naming sql-privileges and a stop, got %+v, windows %q", e, *texts)
	}
}

// A dry run of a session-control statement says it would stop at the
// sql-kill rule: the real run needs an agent's --allow-dangerous.
func TestQuerySessionControlDryRunWouldBeBlocked(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:1/app", "--protected")
	_, _ = invRun(t, "database", "postgres", "query", "pg", "--write", "--dry-run", "select pg_terminate_backend(42)")
	if b := tcl.out.Blocked(); b == nil || b.Code != "POLICY_BLOCKED" || !strings.Contains(b.Message, "sql-kill") {
		t.Fatalf("would_be_blocked = %+v, want POLICY_BLOCKED by sql-kill", b)
	}
}
