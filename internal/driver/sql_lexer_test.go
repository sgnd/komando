package driver

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// TestClassifySQLLexerMatchesServer covers SQL where komando's splitter once
// read the text differently from the server, which let a statement hide
// behind what komando took for a quote or a comment.
func TestClassifySQLLexerMatchesServer(t *testing.T) {
	cases := []struct {
		kind, sql string
		want      Risk
		rule      string
		stmts     int
	}{
		// R1: $ continues a Postgres name, so x$$$ opens no dollar quote
		{"postgres", "select x$$a$ from t; delete from users; select y$a$", RiskDestructive, "sql-delete-no-where", 3},
		{"postgres", "select a$1, b$ from t", RiskRead, "", 1},
		{"postgres", "select $1, $q$ ; drop table x $q$", RiskRead, "", 1},
		{"postgres", "select 1$$ ; drop table x $$", RiskRead, "", 1}, // 1 then a dollar quote, as the server reads it
		{"mysql", "select x$$ from t; drop table users", RiskDestructive, "sql-drop", 2},
		// R2: a Postgres -- comment ends at \r too
		{"postgres", "UPDATE t SET x = 1 WHERE id = 1 -- c\r; DROP TABLE users", RiskDestructive, "sql-drop", 2},
		{"postgres", "SET application_name = 'a' -- c\r; select pg_terminate_backend(1)", RiskDestructive, "sql-kill", 2},
		{"mysql", "select 1 -- c\rdrop table users", RiskRead, "", 1},
		// R2 (MySQL): -- before a control character (0x7f too) starts a comment
		{"mysql", "SELECT 1 --\x7f '\nINTO OUTFILE '/tmp/x' -- '", RiskDestructive, "sql-server-file", 1},
		{"mysql", "SELECT 1 --\t'\nINTO OUTFILE '/tmp/x' -- '", RiskDestructive, "sql-server-file", 1},
		{"mysql", "SELECT 1 --1", RiskRead, "", 1}, // 1 - -1
		// "" inside a quoted name is one "
		{"postgres", `select "a""b" from t`, RiskRead, "", 1},
	}
	for _, c := range cases {
		p, err := ClassifySQL(c.kind, c.sql)
		if err != nil {
			t.Errorf("%s %q: %v", c.kind, c.sql, err)
			continue
		}
		if p.Risk != c.want || len(p.Statements) != c.stmts {
			t.Errorf("%s %q: risk %s with %d statements, want %s with %d", c.kind, c.sql, p.Risk, len(p.Statements), c.want, c.stmts)
		}
		if c.rule != "" && !strings.Contains(strings.Join(p.RuleIDs, ","), c.rule) {
			t.Errorf("%q: rules %v, want %s", c.sql, p.RuleIDs, c.rule)
		}
	}
}

// TestClassifySQLReviewFindings2 lists SQL that once ran with fewer flags
// than it needs (review of 2026-11-04).
func TestClassifySQLReviewFindings2(t *testing.T) {
	cases := []struct {
		kind, sql string
		want      Risk
		rule      string
	}{
		// D1: set_config with a name komando cannot read
		{"postgres", "select set_config(E'standard_conforming_strings', 'off', false)", RiskDestructive, "sql-session-config"},
		{"postgres", "select set_config(U&'standard_conforming_strings', 'off', false)", RiskDestructive, "sql-session-config"},
		{"postgres", "select set_config('application_name', 'x', false)", RiskRead, ""},
		// D4: MySQL SET DEFAULT ROLE writes mysql.default_roles
		{"mysql", "SET DEFAULT ROLE ALL TO 'x'@'%'", RiskDestructive, "sql-privileges"},
		{"mysql", "SET DEFAULT ROLE r FOR u", RiskDestructive, "sql-privileges"},
		// D12: EXPLAIN EXECUTE runs the prepared statement's arguments; setter pragmas
		{"postgres", "EXPLAIN ANALYZE EXECUTE s", RiskDestructive, "sql-opaque"},
		{"postgres", "EXPLAIN EXECUTE s(pg_terminate_backend(1))", RiskDestructive, "sql-opaque"},
		{"postgres", "EXPLAIN (ANALYZE) EXECUTE s", RiskDestructive, "sql-opaque"},
		{"sqlite", "PRAGMA query_only(0)", RiskWrite, ""},
		{"sqlite", "PRAGMA user_version(5)", RiskWrite, ""},
		{"sqlite", "pragma main.user_version(7)", RiskWrite, ""},
		{"sqlite", "pragma wal_checkpoint", RiskWrite, ""},
		{"sqlite", "pragma main.table_info(users)", RiskRead, ""},
		{"sqlite", "pragma user_version", RiskRead, ""},
		// R4: listing and reading server files; large-object writers
		{"postgres", "select pg_ls_dir('.')", RiskDestructive, "sql-server-file"},
		{"postgres", "select * from pg_ls_waldir()", RiskDestructive, "sql-server-file"},
		{"postgres", "select pg_stat_file('postgresql.conf')", RiskDestructive, "sql-server-file"},
		{"postgres", "select lo_unlink(oid) from pg_largeobject_metadata", RiskWrite, ""},
		{"postgres", "select lo_put(1, 0, 'x')", RiskWrite, ""},
		// R5: sequences
		{"postgres", "SELECT setval('seq', 1)", RiskWrite, ""},
		{"postgres", "select pg_catalog.nextval('seq')", RiskWrite, ""},
		{"mysql", "select next value for s", RiskWrite, ""},
		{"postgres", "select currval('seq')", RiskRead, ""},
	}
	for _, c := range cases {
		p, err := ClassifySQL(c.kind, c.sql)
		if err != nil {
			t.Errorf("%s %q: %v", c.kind, c.sql, err)
			continue
		}
		if p.Risk != c.want {
			t.Errorf("%s %q: risk %s, want %s (rules %v)", c.kind, c.sql, p.Risk, c.want, p.RuleIDs)
		}
		if c.rule != "" && !strings.Contains(strings.Join(p.RuleIDs, ","), c.rule) {
			t.Errorf("%q: rules %v, want %s", c.sql, p.RuleIDs, c.rule)
		}
		if c.want != RiskDestructive && len(p.RuleIDs) > 0 {
			t.Errorf("%q: unexpected rules %v", c.sql, p.RuleIDs)
		}
	}
	// statements that cannot be undone are marked, so a dry run skips them
	for _, c := range []struct {
		kind, sql        string
		noTx, noRollback bool
	}{
		{"mysql", "SET DEFAULT ROLE ALL TO 'x'@'%'", true, false},
		{"mysql", "set password = 'x'", true, false},
		{"postgres", "SELECT setval('seq', 1)", false, true},
		{"postgres", "select nextval('seq')", false, false},
		// D3: MySQL runs in the transaction only what is known not to commit
		{"mysql", "CHECK TABLE t", true, false},
		{"mysql", "CACHE INDEX t IN c", true, false},
		{"mysql", "START REPLICA", true, true}, // sql-server-config
		{"mysql", "IMPORT TABLE FROM '/x.sdi'", true, false},
		{"mysql", "CLONE LOCAL DATA DIRECTORY = '/tmp/x'", true, false},
		{"mysql", "BACKUP STAGE START", true, false},
		{"mysql", "XA START 'x'", true, false},
		{"mysql", "BINLOG 'x'", true, false},
		{"mysql", "RESTART", true, false},
		{"mysql", "SHUTDOWN", true, true},
		{"mysql", "frobnicate t", true, false},
		{"mysql", "select * from t", false, false},
		{"mysql", "(select 1) union (select 2)", false, false},
		{"mysql", "insert into t values (1)", false, false},
		{"mysql", "update t set a = 1 where id = 1", false, false},
		{"mysql", "delete from t where id = 1", false, false},
		{"mysql", "replace into t values (1)", false, false},
		{"mysql", "with x as (select 1) select * from x", false, false},
		{"mysql", "show tables", false, false},
		{"mysql", "describe t", false, false},
		{"mysql", "explain select 1", false, false},
		{"mysql", "use app", false, false},
		{"mysql", "set @x = 1", false, false},
		{"mysql", "table t", false, false},
		{"mysql", "values row(1)", false, false},
		{"mysql", "handler t read first", false, false},
		// R5: what a rollback does not undo is marked, so a dry run skips it
		{"postgres", "COPY (SELECT 1) TO PROGRAM 'touch /tmp/x'", false, true},
		{"postgres", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity", false, true},
		{"postgres", "DO $$BEGIN PERFORM setval('s', 500); END$$", false, true},
		{"postgres", "select lo_export(1, '/tmp/x')", false, true},
		{"postgres", "select dblink_exec('dbname=x', 'delete from t')", false, true},
		{"postgres", "select pg_reload_conf()", false, true},
		{"postgres", "select set_config(current_user, 'x', false)", false, true},
		{"postgres", "EXECUTE s", false, true},
		{"mysql", "KILL 5", true, true},
		{"mysql", "SELECT 1 INTO OUTFILE '/tmp/x'", false, true},
		{"mysql", "CALL p()", true, true},
		{"postgres", "delete from t where id = 1", false, false},
	} {
		p, err := ClassifySQL(c.kind, c.sql)
		if err != nil {
			t.Fatal(err)
		}
		if s := p.Statements[0]; s.NoTx != c.noTx || s.NoRollback != c.noRollback {
			t.Errorf("%q: NoTx %v NoRollback %v, want %v %v", c.sql, s.NoTx, s.NoRollback, c.noTx, c.noRollback)
		}
	}
}

func TestClassifySQLRefusesHiddenNames(t *testing.T) {
	for _, c := range []struct{ kind, sql, code string }{
		// R1
		{"postgres", "SET application_name = x$$$ ; COMMIT ; DELETE FROM users ; SET application_name = y$$", "SQL_TX_CONTROL"},
		{"postgres", "SELECT 1abc$$; COMMIT; DELETE FROM users; SELECT $$", "SQL_HIDDEN_CODE"},
		{"postgres", "select 0x1f$$ x $$", "SQL_HIDDEN_CODE"},
		// R2
		{"postgres", "SET application_name = 'a' -- c\r; COMMIT; DELETE FROM users", "SQL_TX_CONTROL"},
		// D1: quoted setting names
		{"postgres", `SET "standard_conforming_strings" = off`, "SQL_STRING_RULES"},
		{"postgres", `RESET "backslash_quote"`, "SQL_STRING_RULES"},
		{"postgres", `SET SESSION "transaction_read_only" = off`, "SQL_TX_CONTROL"},
		{"postgres", `SET "default_transaction_read_only" TO off`, "SQL_TX_CONTROL"},
		{"postgres", "select set_config($$standard_conforming_strings$$, 'off', false)", "SQL_STRING_RULES"},
		// D2: U& names are not decoded, so they are refused
		{"postgres", `SELECT U&"\0064blink_exec"('dbname=x', 'DROP TABLE users')`, "SQL_HIDDEN_CODE"},
		{"postgres", `select u&"\0070g_terminate_backend"(1)`, "SQL_HIDDEN_CODE"},
		{"postgres", `SELECT U&"!0070g_terminate_backend" UESCAPE '!'(1)`, "SQL_HIDDEN_CODE"},
		{"postgres", `SET U&"standard_conforming_strings" = off`, "SQL_HIDDEN_CODE"},
		// D3: backtick names in MySQL
		{"mysql", "SET `autocommit` = 0, `autocommit` = 1", "SQL_TX_CONTROL"},
		{"mysql", "SET @@session.`autocommit` = 1", "SQL_TX_CONTROL"},
		{"mysql", "SET @@`autocommit` = 1", "SQL_TX_CONTROL"},
		{"mysql", "SET `transaction_read_only` = 0", "SQL_TX_CONTROL"},
		{"mysql", "SET `sql_mode` = 'ANSI_QUOTES'", "SQL_STRING_RULES"},
		{"mysql", "SET @@session.'autocommit' = 1", "SQL_TX_CONTROL"},
		{"mysql", `SET @@session.'auto\commit' = 1`, "SQL_HIDDEN_CODE"},
		// R2 (MySQL): whether -- before a non-ASCII byte starts a comment
		// depends on the character set
		{"mysql", "SELECT 1 --\x80 '\nINTO OUTFILE '/tmp/x' -- '", "SQL_HIDDEN_CODE"},
		{"mysql", "SELECT 1 --\xc2\xa0 '\nINTO OUTFILE '/tmp/x' -- '", "SQL_HIDDEN_CODE"},
		// D1: the client character set decides how the server reads a backslash
		{"postgres", "SET client_encoding = 'SJIS'", "SQL_STRING_RULES"},
		{"postgres", "SET client_encoding TO 'GBK'", "SQL_STRING_RULES"},
		{"postgres", `SET "client_encoding" = 'BIG5'`, "SQL_STRING_RULES"},
		{"postgres", "SET NAMES 'GBK'", "SQL_STRING_RULES"},
		{"postgres", "RESET client_encoding", "SQL_STRING_RULES"},
		{"postgres", "SELECT set_config('client_encoding', 'BIG5', false)", "SQL_STRING_RULES"},
		{"mysql", "SET NAMES gbk", "SQL_STRING_RULES"},
		{"mysql", "SET CHARACTER SET sjis", "SQL_STRING_RULES"},
		{"mysql", "SET CHARSET big5", "SQL_STRING_RULES"},
		{"mysql", "SET character_set_client = sjis", "SQL_STRING_RULES"},
		{"mysql", "SET @@session.character_set_client = gbk", "SQL_STRING_RULES"},
		{"mysql", "SET SESSION `character_set_client` = gbk", "SQL_STRING_RULES"},
	} {
		_, err := ClassifySQL(c.kind, c.sql)
		if e, ok := err.(*out.Error); !ok || e.Code != c.code {
			t.Errorf("%s %q: want %s, got %v", c.kind, c.sql, c.code, err)
		}
	}
}
