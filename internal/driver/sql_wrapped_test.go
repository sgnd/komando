package driver

import "testing"

// MariaDB's SET STATEMENT var=value FOR <statement> runs the statement
// after FOR: it is rated as that statement, never as a harmless SET.
func TestSetStatementForIsTheWrappedStatement(t *testing.T) {
	for sql, want := range map[string]Risk{
		"SET STATEMENT max_statement_time=0 FOR DROP TABLE t":                                    RiskDestructive,
		"SET STATEMENT max_statement_time=0 FOR TRUNCATE t":                                      RiskDestructive,
		"SET STATEMENT max_statement_time=0 FOR GRANT ALL ON *.* TO x":                           RiskDestructive,
		"SET STATEMENT max_statement_time=0 FOR DELETE FROM t WHERE id=1":                        RiskWrite,
		"set statement max_statement_time=1, sort_buffer_size=1 for update t set a=1 where id=2": RiskWrite,
		"SET STATEMENT max_statement_time=0 FOR SELECT 1":                                        RiskRead,
		"SET STATEMENT max_statement_time=0":                                                     RiskWrite, // no FOR: not a statement komando knows
		"SET STATEMENT max_statement_time=0 FOR":                                                 RiskWrite,
		"SET max_statement_time=0":                                                               RiskRead,
	} {
		for _, kind := range []string{"mysql", "mariadb"} {
			if _, ok := dialects[kind]; !ok {
				continue
			}
			p, err := ClassifySQL(kind, sql)
			if err != nil {
				t.Errorf("%s %q: %v", kind, sql, err)
				continue
			}
			if p.Risk != want {
				t.Errorf("%s %q: risk %v, want %v", kind, sql, p.Risk, want)
			}
		}
	}
}

// Postgres functions whose effect outlasts the statement, and that a
// read-only transaction does not stop, are not plain reads.
func TestPostgresSideEffectFunctions(t *testing.T) {
	for _, sql := range []string{
		"SELECT pg_stat_statements_reset()",
		"SELECT pg_replication_slot_advance('s', '0/1')",
		"SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL)",
		"SELECT * FROM pg_logical_slot_get_binary_changes('s', NULL, NULL)",
		"SELECT pg_copy_physical_replication_slot('a', 'b')",
		"SELECT pg_copy_logical_replication_slot('a', 'b')",
		"SELECT pg_logical_emit_message(false, 'p', 'x')",
		"SELECT pg_backup_start('x')",
		"SELECT pg_backup_stop()",
		"SELECT pg_start_backup('x')",
		"SELECT pg_stop_backup()",
	} {
		p, err := ClassifySQL("postgres", sql)
		if err != nil {
			t.Errorf("%q: %v", sql, err)
			continue
		}
		if p.Risk != RiskDestructive || !p.Statements[0].NoRollback {
			t.Errorf("%q: risk %v, no_rollback %v; want destructive, true", sql, p.Risk, p.Statements[0].NoRollback)
		}
	}
	// looking at a slot's changes without consuming them, and the statistics views, stay reads
	for _, sql := range []string{"SELECT * FROM pg_logical_slot_peek_changes('s', NULL, NULL)", "SELECT * FROM pg_stat_statements", "SELECT * FROM pg_replication_slots"} {
		if p, err := ClassifySQL("postgres", sql); err != nil || p.Risk != RiskRead {
			t.Errorf("%q: %v, %v", sql, p.Risk, err)
		}
	}
}

// The wrapped statement also decides how the statement is run: MariaDB
// commits DDL at once, so SET STATEMENT ... FOR CREATE TABLE cannot run
// inside the transaction a dry run rolls back, and FOR SELECT has rows.
func TestSetStatementForRunsAsTheWrappedStatement(t *testing.T) {
	for _, c := range []struct{ wrapped, plain string }{
		{"SET STATEMENT a=1 FOR DROP TABLE t", "DROP TABLE t"},
		{"SET STATEMENT a=1 FOR CREATE TABLE x (a int)", "CREATE TABLE x (a int)"},
		{"SET STATEMENT a=1 FOR ALTER TABLE x ADD b int", "ALTER TABLE x ADD b int"},
		{"SET STATEMENT a=1 FOR SELECT 1", "SELECT 1"},
		{"SET STATEMENT a=1 FOR DELETE FROM t WHERE id=1", "DELETE FROM t WHERE id=1"},
	} {
		w, err := ClassifySQL("mysql", c.wrapped)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ClassifySQL("mysql", c.plain)
		if err != nil {
			t.Fatal(err)
		}
		a, b := w.Statements[0], p.Statements[0]
		if a.Keyword != b.Keyword || a.Rows != b.Rows || a.NoTx != b.NoTx || a.NoRollback != b.NoRollback || a.Risk != b.Risk || a.Unknown != b.Unknown {
			t.Errorf("%q: %+v, but %q: %+v", c.wrapped, a, c.plain, b)
		}
	}
	// the functions a read-only transaction does not stop
	for _, sql := range []string{"SELECT pg_sync_replication_slots()", "SELECT pg_truncate_visibility_map('t')"} {
		if p, err := ClassifySQL("postgres", sql); err != nil || p.Risk != RiskDestructive {
			t.Errorf("%q: %v, %v", sql, p.Risk, err)
		}
	}
}
