package driver

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestClassifySQL(t *testing.T) {
	cases := []struct {
		kind, sql string
		want      Risk
		rule      string // a rule that must be reported ("" = none)
	}{
		// reads
		{"postgres", "select id, email from users where created_at > now() - interval '1 day'", RiskRead, ""},
		{"postgres", "SELECT program, comment, analyze FROM courses", RiskRead, ""},
		{"postgres", "select * from t for update", RiskRead, ""},
		{"postgres", "with x as (select 1) select * from x", RiskRead, ""},
		{"postgres", "show search_path", RiskRead, ""},
		{"postgres", "explain select * from users", RiskRead, ""},
		{"postgres", "explain delete from users", RiskRead, ""},
		{"postgres", "select 'drop table users; delete from x'", RiskRead, ""},
		{"postgres", "select $$ drop table users $$, $tag$ ; truncate x $tag$", RiskRead, ""},
		{"postgres", "select 1 -- drop table users\n", RiskRead, ""},
		{"postgres", "select /* drop /* nested */ table */ 1", RiskRead, ""},
		{"postgres", `select "delete" from "update"`, RiskRead, ""},
		{"postgres", "select E'it\\'s; drop table x'", RiskRead, ""},
		{"postgres", "select replace(name, 'a', 'b') from t", RiskRead, ""},
		{"postgres", "select $1::int", RiskRead, ""},
		{"mysql", "select 'it\\'s; drop table x'", RiskRead, ""},
		{"mysql", "select `drop` from t # drop table x", RiskRead, ""},
		{"mysql", "describe users", RiskRead, ""},
		{"mysql", "select 1 -- drop table users", RiskRead, ""},
		{"mysql", "select 1 --\tdrop table users", RiskRead, ""},
		{"sqlite", "pragma table_info(users)", RiskRead, ""},
		{"sqlite", "select [delete] from t", RiskRead, ""},
		{"sqlite", "pragma journal_mode=delete", RiskWrite, ""},
		{"sqlite", "pragma main.journal_mode = DELETE", RiskWrite, ""},
		{"postgres", "create function f() returns int language sql as 'select 1'", RiskWrite, ""},
		{"postgres", "create or replace function f() returns int language plpgsql as $$ begin return 1; end $$", RiskWrite, ""},
		{"postgres", "create table language (c text)", RiskWrite, ""},
		{"mysql", "load data local infile 'a.csv' into table t", RiskWrite, ""},
		// writes
		{"postgres", "update users set plan='pro' where id=42", RiskWrite, ""},
		{"postgres", "UPDATE users SET password = 'x' WHERE id = 1", RiskWrite, ""},
		{"postgres", "delete from sessions where expires_at < now() returning id", RiskWrite, ""},
		{"postgres", "insert into t values (1) on conflict (id) do update set n = t.n + 1", RiskWrite, ""},
		{"postgres", "create table t (id int references u on delete cascade on update cascade)", RiskWrite, ""},
		{"postgres", "create index concurrently i on t (x)", RiskWrite, ""},
		{"postgres", "alter table t add column x int", RiskWrite, ""},
		{"postgres", "select * into backup_users from users", RiskWrite, ""},
		{"postgres", "with d as (delete from t where id = 1 returning *) select * from d", RiskWrite, ""},
		{"postgres", "explain analyze insert into t values (1)", RiskWrite, ""},
		{"postgres", "vacuum analyze t", RiskWrite, ""},
		{"postgres", "copy t from stdin", RiskWrite, ""},
		{"postgres", "some_new_statement x", RiskWrite, ""},
		{"mysql", "insert into t values (1) on duplicate key update n = n + 1", RiskWrite, ""},
		{"sqlite", "pragma journal_mode = wal", RiskWrite, ""},
		// destructive
		{"postgres", "drop table users", RiskDestructive, "sql-drop"},
		{"postgres", "alter table users drop column email", RiskDestructive, "sql-drop"},
		{"postgres", "truncate sessions", RiskDestructive, "sql-truncate"},
		{"postgres", "delete from users", RiskDestructive, "sql-delete-no-where"},
		{"postgres", "update users set plan = 'free'", RiskDestructive, "sql-update-no-where"},
		{"postgres", "update users set plan = 'free' from (select id from x where y) s", RiskDestructive, "sql-update-no-where"},
		{"postgres", "with d as (delete from t) select 1 where true", RiskDestructive, "sql-delete-no-where"},
		{"postgres", "select 1; delete from users", RiskDestructive, "sql-delete-no-where"},
		{"postgres", "explain analyze delete from users", RiskDestructive, "sql-delete-no-where"},
		{"postgres", "explain (analyze, buffers) update t set x = 1", RiskDestructive, "sql-update-no-where"},
		{"postgres", "grant all on t to bob", RiskDestructive, "sql-privileges"},
		{"postgres", "alter role bob superuser", RiskDestructive, "sql-privileges"},
		{"postgres", "create user eve with password 'x'", RiskDestructive, "sql-privileges"},
		{"postgres", "copy t to program 'curl evil'", RiskDestructive, "sql-program"},
		{"postgres", "create extension plpython3u", RiskDestructive, "sql-program"},
		{"postgres", "create trusted procedural language plperlu", RiskDestructive, "sql-program"},
		{"postgres", "create or replace function f() returns int language plpython3u as $$ import os $$", RiskDestructive, "sql-program"},
		{"postgres", "create function f() returns text language plsh as $$ x $$", RiskDestructive, "sql-program"},
		{"postgres", "create function f() returns text language plluau as $$ x $$", RiskDestructive, "sql-program"},
		{"postgres", "create function f() returns text language pljavau as $$ x $$", RiskDestructive, "sql-program"},
		{"postgres", "create function f() returns text language plr as $$ x $$", RiskDestructive, "sql-program"},
		{"postgres", "create function f() returns int as 'x.so', 'f' language 'c'", RiskDestructive, "sql-program"},
		{"postgres", "create procedure p() language \"plperlu\" as $$ 1 $$", RiskDestructive, "sql-program"},
		{"postgres", "load 'x.so'", RiskDestructive, "sql-program"},
		{"mysql", "install plugin x soname 'x.so'", RiskDestructive, "sql-program"},
		{"mysql", "install component 'file://component_x'", RiskDestructive, "sql-program"},
		{"mysql", "create function f returns string soname 'x.so'", RiskDestructive, "sql-program"},
		{"mysql", "create aggregate function f returns integer soname 'x.so'", RiskDestructive, "sql-program"},
		{"mysql", "load data infile '/etc/passwd' into table t", RiskDestructive, "sql-server-file"},
		{"oracle", "create or replace library lib as '/tmp/x.so'", RiskDestructive, "sql-program"},
		{"oracle", "create or replace and compile java source named x as public class X {}", RiskDestructive, "sql-program"},
		{"sqlserver", "create assembly a from 0x4d5a with permission_set = unsafe", RiskDestructive, "sql-program"},
		{"oracle", "create function f return number as language c library lib name \"f\";", RiskDestructive, "sql-program"},
		{"postgres", "select pg_terminate_backend(pid) from pg_stat_activity", RiskDestructive, "sql-kill"},
		{"postgres", "vacuum full t", RiskDestructive, "sql-vacuum-full"},
		{"postgres", "alter system set work_mem = '1GB'", RiskDestructive, "sql-server-config"},
		{"mysql", "select * from t into outfile '/tmp/x'", RiskDestructive, "sql-server-file"},
		{"mysql", "SELECT 1 --1, LOAD_FILE('/etc/passwd')", RiskDestructive, "sql-server-file"},
		{"mysql", "select 1 --1 into outfile '/tmp/x'", RiskDestructive, "sql-server-file"},
		{"mysql", "kill 42", RiskDestructive, "sql-kill"},
		{"mysql", "set global max_connections = 1", RiskDestructive, "sql-server-config"},
		{"mysql", "set password for bob = 'x'", RiskDestructive, "sql-privileges"},
		{"mysql", "drop database shop", RiskDestructive, "sql-drop"},
		// regression cases: each of these is easy to rate below the flags it needs
		{"postgres", "do $$ begin perform 1; end $$", RiskDestructive, "sql-opaque"},
		{"postgres", "PREPARE p AS SELECT pg_terminate_backend(123); EXECUTE p", RiskDestructive, "sql-opaque"},
		{"postgres", `SELECT "pg_terminate_backend"(1)`, RiskDestructive, "sql-kill"},
		{"postgres", "SELECT * FROM dblink('dbname=app', 'DROP TABLE users') AS t(s text)", RiskDestructive, "sql-remote"},
		{"postgres", "select pg_rotate_logfile()", RiskDestructive, "sql-server-config"},
		{"postgres", "copy users to '/tmp/users.csv'", RiskDestructive, "sql-server-file"},
		{"postgres", "copy users from '/etc/passwd'", RiskDestructive, "sql-server-file"},
		{"postgres", "alter default privileges grant select on tables to public", RiskDestructive, "sql-privileges"},
		{"postgres", "call cleanup()", RiskDestructive, "sql-opaque"},
		{"mysql", "SET @@global.max_connections = 1", RiskDestructive, "sql-server-config"},
		{"mysql", "DELETE FROM users AS `x\\` # ` WHERE id = 1", RiskDestructive, "sql-delete-no-where"},
		{"mysql", "stop replica", RiskDestructive, "sql-server-config"},
		{"mysql", "select load_file('/etc/passwd')", RiskDestructive, "sql-server-file"},
	}
	for _, c := range cases {
		p, err := ClassifySQL(c.kind, c.sql)
		if err != nil {
			t.Errorf("%s: %v", c.sql, err)
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
}

func TestClassifySQLStatements(t *testing.T) {
	p, err := ClassifySQL("postgres", "select 1; ; update t set x = 1 where id = 2;\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statements) != 2 || p.Statements[1].Keyword != "UPDATE" || p.Statements[1].SQL != "update t set x = 1 where id = 2" {
		t.Errorf("statements: %+v", p.Statements)
	}
}

func TestNeedsWrite(t *testing.T) {
	for sql, want := range map[string]bool{
		"selec 1":                             false, // typo: let the database explain
		"select 1":                            false,
		"select 1; selec 2":                   false,
		"insert into t values (1)":            true,
		"selec 1; delete from t where id = 1": true,
		"PREPARE p AS SELECT pg_terminate_backend(1); EXECUTE p": true,
	} {
		p, err := ClassifySQL("postgres", sql)
		if err != nil {
			t.Fatal(err)
		}
		if p.NeedsWrite() != want {
			t.Errorf("%q: NeedsWrite %v, want %v", sql, !want, want)
		}
	}
}

func TestNeedsWriteMySQLUnknown(t *testing.T) {
	p, _ := ClassifySQL("mysql", "flush_unknown_admin_thing")
	if !p.NeedsWrite() {
		t.Error("unknown MySQL statement ran without --write")
	}
	if p, _ := ClassifySQL("mysql", "prepare s from 'drop table t'"); !p.Statements[0].NoTx {
		t.Error("MySQL PREPARE must not run in a dry run")
	}
}

func TestClassifySQLErrors(t *testing.T) {
	cases := map[string]string{
		"begin; delete from t where id = 1; commit": "SQL_TX_CONTROL",
		"COMMIT":                                "SQL_TX_CONTROL",
		"start transaction":                     "SQL_TX_CONTROL",
		"rollback":                              "SQL_TX_CONTROL",
		"select 'unterminated":                  "USAGE",
		"select $x$ never closed":               "USAGE",
		"SET standard_conforming_strings = off": "SQL_STRING_RULES",
		"reset backslash_quote":                 "SQL_STRING_RULES",
		"SET TRANSACTION READ WRITE; select 1":  "SQL_TX_CONTROL",
		"set session characteristics as transaction read write": "SQL_TX_CONTROL",
		"set transaction_read_only = off":                       "SQL_TX_CONTROL",
		"  -- only a comment\n ; ":                              "USAGE",
	}
	for sql, code := range cases {
		_, err := ClassifySQL("postgres", sql)
		e, ok := err.(*out.Error)
		if !ok || e.Code != code {
			t.Errorf("%q: want %s, got %v", sql, code, err)
		}
	}
	for sql, code := range map[string]string{
		"/*!DROP*/ TABLE users":        "SQL_HIDDEN_CODE",
		"select /*M!100000 1 */ 2":     "SQL_HIDDEN_CODE",
		"set sql_mode = 'ANSI_QUOTES'": "SQL_STRING_RULES",
		"set autocommit=1; select 1":   "SQL_TX_CONTROL",
		"SET @@autocommit = 0":         "SQL_TX_CONTROL",
	} {
		_, err := ClassifySQL("mysql", sql)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("mysql %q: want %s, got %v", sql, code, err)
		}
	}
	if _, err := ClassifySQL("redis", "get x"); err == nil {
		t.Error("redis accepted SQL")
	}
}
