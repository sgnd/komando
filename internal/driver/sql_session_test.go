package driver

import (
	"slices"
	"testing"
)

// TestSessionControlSQL pins how SQL that ends or cancels another session,
// reloads the server's configuration or rotates its log is rated, in every
// spelling a query may use. Each form needs --write and --allow-dangerous,
// and a dry run never executes it: a rollback does not undo it.
func TestSessionControlSQL(t *testing.T) {
	cases := []struct {
		name, kind, sql, rule string
	}{
		{"terminate", "postgres", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity", "sql-kill"},
		{"cancel", "postgres", "SELECT pg_cancel_backend(42)", "sql-kill"},
		{"reload conf", "postgres", "SELECT pg_reload_conf()", "sql-server-config"},
		{"rotate logfile", "postgres", "SELECT pg_rotate_logfile()", "sql-server-config"},
		{"schema prefix", "postgres", "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_stat_activity", "sql-kill"},
		{"schema prefix quoted", "postgres", `SELECT pg_catalog . "pg_reload_conf" ()`, "sql-server-config"},
		{"in a subquery", "postgres", "SELECT * FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity) s", "sql-kill"},
		{"in a CTE", "postgres", "WITH x AS (SELECT pg_cancel_backend(1)) SELECT * FROM x", "sql-kill"},
		{"mixed case", "postgres", "SeLeCt Pg_Cancel_Backend(1)", "sql-kill"},
		{"block comment before the bracket", "postgres", "SELECT pg_terminate_backend /* c */ (1)", "sql-kill"},
		{"line comment before the bracket", "postgres", "SELECT pg_rotate_logfile -- c\n()", "sql-server-config"},
		{"mysql kill", "mysql", "KILL 5", "sql-kill"},
		{"mysql kill query", "mysql", "KILL QUERY 5", "sql-kill"},
		{"mysql kill connection", "mysql", "kill connection 5", "sql-kill"},
		{"mysql kill after a comment", "mysql", "/* x */ KILL 5", "sql-kill"},
		// db explain --analyze runs the statement under the prefix it adds
		// (internal/cli/db.go): Postgres EXPLAIN (ANALYZE, BUFFERS), MySQL EXPLAIN ANALYZE
		{"db explain --analyze terminate", "postgres", "EXPLAIN (ANALYZE, BUFFERS) SELECT pg_terminate_backend(pid) FROM pg_stat_activity", "sql-kill"},
		{"db explain --analyze cancel in a CTE", "postgres", "EXPLAIN (ANALYZE, BUFFERS) WITH x AS (SELECT pg_cancel_backend(1)) SELECT * FROM x", "sql-kill"},
		{"db explain --analyze reload conf", "postgres", "EXPLAIN (ANALYZE, BUFFERS) SELECT pg_catalog.pg_reload_conf()", "sql-server-config"},
		{"db explain --analyze mysql kill", "mysql", "EXPLAIN ANALYZE KILL QUERY 5", "sql-kill"},	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ClassifySQL(c.kind, c.sql)
			if err != nil {
				t.Fatal(err)
			}
			if p.Risk != RiskDestructive || !slices.Contains(p.RuleIDs, c.rule) {
				t.Errorf("%q: risk %v, rules %v; want destructive with %s", c.sql, p.Risk, p.RuleIDs, c.rule)
			}
			if !p.NeedsWrite() {
				t.Errorf("%q: runs without --write", c.sql)
			}
			if !p.Statements[0].NoRollback {
				t.Errorf("%q: a dry run would execute it", c.sql)
			}
		})
	}
}
