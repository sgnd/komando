package dbx

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// These tests prove that SQL which hides a COMMIT from komando's splitter
// cannot change data: the classifier refuses it, and when a statement gets
// past the classifier anyway the database layer stops it. They run when
// KOMANDO_PGTEST (postgres://...) or KOMANDO_MYTEST (mysql://..., MySQL or
// MariaDB) names a disposable server; the password comes from
// KOMANDO_PGTEST_PASSWORD / KOMANDO_MYTEST_PASSWORD.

func liveDB(t *testing.T, env string, readOnly bool, query string) *sql.DB {
	t.Helper()
	u := os.Getenv(env)
	if u == "" {
		t.Skipf("set %s to run", env)
	}
	if query != "" {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + query
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, os.Getenv(env+"_PASSWORD"), nil, readOnly, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// raw is a plan as if the classifier had rated the text read: the
// database layer must hold on its own.
func raw(sqls ...string) driver.SQLPlan {
	var p driver.SQLPlan
	for _, s := range sqls {
		kw := strings.ToUpper(strings.Fields(s)[0])
		p.Statements = append(p.Statements, driver.Statement{SQL: s, Keyword: kw, Rows: kw == "SELECT" || kw == "SHOW"})
	}
	return p
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func errCode(err error) string {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func TestHiddenCommitPostgresLive(t *testing.T) {
	ctx := context.Background()
	rw := liveDB(t, "KOMANDO_PGTEST", false, "")
	for _, q := range []string{"DROP TABLE IF EXISTS komando_victim", "CREATE TABLE komando_victim (id int)", "INSERT INTO komando_victim VALUES (1)",
		"DROP SEQUENCE IF EXISTS komando_seq", "CREATE SEQUENCE komando_seq"} {
		if _, err := rw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { rw.Exec("DROP TABLE IF EXISTS komando_victim"); rw.Exec("DROP SEQUENCE IF EXISTS komando_seq") })

	// each payload must be refused or fail, and change nothing
	payloads := []string{
		"SET application_name = x$$$ ; COMMIT ; DELETE FROM komando_victim ; SET application_name = y$$", // R1
		"SET application_name = 'a' -- c\r; COMMIT; DELETE FROM komando_victim",                          // R2
		`SET "standard_conforming_strings" = off`,                                                        // D1, step 1
		`SET application_name = '\''; COMMIT; DELETE FROM komando_victim; --'`,                           // D1, step 2
		`SELECT * FROM U&"\0064blink_exec"('dbname=postgres', 'DELETE FROM komando_victim')`,             // D2
		"SELECT 1abc$$; COMMIT; DELETE FROM komando_victim; SELECT $$",                                   // number$ before Postgres 15
	}
	ro := liveDB(t, "KOMANDO_PGTEST", true, "")
	for _, p := range payloads {
		for _, write := range []bool{false, true} {
			plan, err := driver.ClassifySQL("postgres", p)
			if err == nil && (write || !plan.NeedsWrite()) {
				db := ro
				if write {
					db = rw
				}
				_, err = Run(ctx, db, "postgres", plan, Options{Write: write, DryRun: true})
			}
			if err == nil && !write && p != payloads[3] {
				t.Errorf("%q ran without --write", p) // only the D1 string is harmless once its SET is refused
			}
			if n := count(t, rw, "komando_victim"); n != 1 {
				t.Fatalf("%q (write=%v) changed data: %d rows", p, write, n)
			}
		}
	}

	// past the classifier: the extended protocol refuses a second command
	simple := liveDB(t, "KOMANDO_PGTEST", true, "default_query_exec_mode=simple_protocol")
	for _, db := range []*sql.DB{ro, simple, rw} {
		_, err := Run(ctx, db, "postgres", raw("SET application_name = 'a'; COMMIT; DELETE FROM komando_victim"), Options{Write: db == rw, DryRun: true})
		if err == nil || !strings.Contains(err.Error(), "multiple commands") {
			t.Errorf("multi-command text: %v", err)
		}
	}
	// a COMMIT on its own ends the transaction: nothing after it runs
	_, err := Run(ctx, rw, "postgres", raw("INSERT INTO komando_victim VALUES (2)", "COMMIT", "DELETE FROM komando_victim"), Options{Write: true, DryRun: true})
	if errCode(err) != "SQL_TX_CONTROL" {
		t.Errorf("escaped COMMIT: %v", err)
	}
	if n := count(t, rw, "komando_victim"); n != 2 {
		t.Errorf("after the escaped COMMIT: %d rows, want 2 (the DELETE must not run)", n)
	}
	rw.Exec("DELETE FROM komando_victim WHERE id = 2")
	// and a read-only session stays read-only after it
	res, err := Run(ctx, ro, "postgres", raw("SHOW default_transaction_read_only"), Options{})
	if err != nil || res.Results[0].Rows[0][0] != "on" {
		t.Errorf("read-only session: %+v %v", res, err)
	}

	// statements without rows still report what they changed
	plan, _ := driver.ClassifySQL("postgres", "UPDATE komando_victim SET id = 1 WHERE id = 1")
	res, err = Run(ctx, rw, "postgres", plan, Options{Write: true, DryRun: true})
	if err != nil || res.Results[0].RowsAffected == nil || *res.Results[0].RowsAffected != 1 {
		t.Errorf("rows affected: %+v %v", res, err)
	}
	// and statements that cannot run in a transaction still work
	plan, _ = driver.ClassifySQL("postgres", "VACUUM komando_victim")
	if _, err := Run(ctx, rw, "postgres", plan, Options{Write: true}); err != nil {
		t.Errorf("vacuum: %v", err)
	}

	// a dry run does not call setval, which a rollback would not undo
	plan, _ = driver.ClassifySQL("postgres", "SELECT setval('komando_seq', 100)")
	res, err = Run(ctx, rw, "postgres", plan, Options{Write: true, DryRun: true})
	if err != nil || res.Results[0].Skipped == "" {
		t.Errorf("setval dry run: %+v %v", res, err)
	}
	var next int
	if err := rw.QueryRow("SELECT nextval('komando_seq')").Scan(&next); err != nil || next != 1 {
		t.Errorf("the dry run moved the sequence: %d %v", next, err)
	}
}

func TestHiddenCommitMySQLLive(t *testing.T) {
	ctx := context.Background()
	rw := liveDB(t, "KOMANDO_MYTEST", false, "")
	for _, q := range []string{"DROP TABLE IF EXISTS komando_victim", "CREATE TABLE komando_victim (id int) ENGINE=InnoDB", "INSERT INTO komando_victim VALUES (1)"} {
		if _, err := rw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { rw.Exec("DROP TABLE IF EXISTS komando_victim") })
	ro := liveDB(t, "KOMANDO_MYTEST", true, "")

	// D3: quoted names do not get past the setting check
	for _, p := range []string{"SET `autocommit` = 0, `autocommit` = 1", "SET @@session.`autocommit` = 1", "SET `transaction_read_only` = 0"} {
		if _, err := driver.ClassifySQL("mysql", p); errCode(err) != "SQL_TX_CONTROL" {
			t.Errorf("%q: %v", p, err)
		}
	}
	// past the classifier: one statement per call (multiStatements is off)
	if _, err := Run(ctx, ro, "mysql", raw("SELECT 1; DELETE FROM komando_victim"), Options{}); err == nil {
		t.Error("multi-statement text ran")
	}
	// an implicit commit is noticed before the next statement runs
	for _, o := range []Options{{}, {Write: true, DryRun: true}} {
		db := ro
		if o.Write {
			db = rw
		}
		_, err := Run(ctx, db, "mysql", raw("SET autocommit = 0, autocommit = 1", "DELETE FROM komando_victim"), o)
		if errCode(err) != "SQL_TX_CONTROL" {
			t.Errorf("escaped transaction (write=%v): %v", o.Write, err)
		}
		if n := count(t, rw, "komando_victim"); n != 1 {
			t.Fatalf("write=%v: %d rows", o.Write, n)
		}
	}
	// a read-only run makes the session read-only, and puts it back after
	// (servers older than MySQL 5.7.20 and MariaDB 11.1 name it tx_read_only)
	res, err := Run(ctx, ro, "mysql", raw("SELECT @@SESSION.transaction_read_only + 0"), Options{})
	if err != nil || mysqlInt(res.Results[0].Rows[0][0]) != 1 {
		t.Errorf("read-only session: %+v %v", res, err)
	}
	var after int
	if err := ro.QueryRow("SELECT @@SESSION.transaction_read_only + 0").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Errorf("session left read-only after the run")
	}
	// ordinary runs still work, with the savepoint check in place
	plan, _ := driver.ClassifySQL("mysql", "UPDATE komando_victim SET id = 1 WHERE id = 1")
	if res, err := Run(ctx, rw, "mysql", plan, Options{Write: true, DryRun: true}); err != nil || !res.RolledBack {
		t.Errorf("dry run: %+v %v", res, err)
	}
}

func mysqlInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case []byte:
		if string(x) == "1" {
			return 1
		}
	case string:
		if x == "1" {
			return 1
		}
	}
	return 0
}

func TestStartupParamRefused(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&pgconn.PgError{Code: "08P01", Message: "unsupported startup parameter: default_transaction_read_only"}, true}, // PgBouncer
		{&pgconn.PgError{Code: "08P01", Message: "protocol violation"}, true},
		{errors.New("server rejected default_transaction_read_only"), true},
		{&pgconn.PgError{Code: "28P01", Message: "password authentication failed"}, false},
		{errors.New("dial tcp: connection refused"), false},
	} {
		if got := startupParamRefused(c.err); got != c.want {
			t.Errorf("%v: %v, want %v", c.err, got, c.want)
		}
	}
}

// openErr opens env's server with extra URL settings and returns the error.
func openErr(t *testing.T, env, query string) error {
	t.Helper()
	u := os.Getenv(env) + "?" + query
	if strings.Contains(os.Getenv(env), "?") {
		u = os.Getenv(env) + "&" + query
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, os.Getenv(env+"_PASSWORD"), nil, true, "test")
	if err == nil {
		db.Close()
	}
	return err
}

// More Postgres cases: a client encoding that hides a backslash, COMMIT
// AND CHAIN, and dry runs of what a rollback does not undo.
func TestTxSafetyPostgresLive2(t *testing.T) {
	ctx := context.Background()
	rw := liveDB(t, "KOMANDO_PGTEST", false, "")
	ro := liveDB(t, "KOMANDO_PGTEST", true, "")
	for _, q := range []string{"DROP TABLE IF EXISTS komando_victim2", "CREATE TABLE komando_victim2 (id int)",
		"DROP SEQUENCE IF EXISTS komando_seq2", "CREATE SEQUENCE komando_seq2"} {
		if _, err := rw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		rw.Exec("DROP TABLE IF EXISTS komando_victim2")
		rw.Exec("DROP SEQUENCE IF EXISTS komando_seq2")
	})

	// D1: SJIS reads \x95\x5c as one character, so the server sees no backslash
	for _, p := range []string{
		"SET client_encoding = 'SJIS'; SELECT E'\x95\x5c' , pg_terminate_backend(1) -- '",
		"SET NAMES 'GBK'; SELECT 1",
		"SELECT set_config('client_encoding', 'BIG5', false)",
	} {
		if _, err := driver.ClassifySQL("postgres", p); errCode(err) != "SQL_STRING_RULES" {
			t.Errorf("%q: %v", p, err)
		}
	}
	if err := openErr(t, "KOMANDO_PGTEST", "client_encoding=SJIS"); errCode(err) != "SQL_STRING_RULES" {
		t.Errorf("SJIS connection: %v", err)
	}
	if err := openErr(t, "KOMANDO_PGTEST", "client_encoding=LATIN1"); err != nil {
		t.Errorf("LATIN1 connection: %v", err) // ASCII-safe
	}

	// COMMIT AND CHAIN keeps a transaction open, but not komando's
	for _, o := range []Options{{Write: true, DryRun: true}, {}} {
		db, first := rw, "INSERT INTO komando_victim2 VALUES (1)"
		if !o.Write {
			db, first = ro, "SELECT 1"
		}
		res, err := Run(ctx, db, "postgres", raw(first, "COMMIT AND CHAIN", "INSERT INTO komando_victim2 VALUES (2)"), o)
		if errCode(err) != "SQL_TX_CONTROL" || res != nil {
			t.Errorf("AND CHAIN (write=%v): %+v %v", o.Write, res, err)
		}
	}
	if n := count(t, rw, "komando_victim2"); n != 1 { // the INSERT before the COMMIT is real; the one after never ran
		t.Errorf("after AND CHAIN: %d rows, want 1", n)
	}

	// R5: a dry run skips what a rollback does not undo
	victim := liveDB(t, "KOMANDO_PGTEST", false, "application_name=komando_victim2")
	vc, err := victim.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vc.Close()
	for _, p := range []string{
		"COPY (SELECT 1) TO PROGRAM 'true'",
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'komando_victim2'",
		"DO $$BEGIN PERFORM setval('komando_seq2', 500); END$$",
	} {
		plan, err := driver.ClassifySQL("postgres", p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Run(ctx, rw, "postgres", plan, Options{Write: true, DryRun: true})
		if err != nil || res.Results[0].Skipped == "" {
			t.Errorf("%q dry run: %+v %v", p, res, err)
		}
		if _, err := Run(ctx, ro, "postgres", plan, Options{}); errCode(err) != "WRITE_REQUIRES_FLAG" {
			t.Errorf("%q read-only: %v", p, err) // a read-only transaction does not stop these either
		}
	}
	if err := vc.PingContext(ctx); err != nil {
		t.Errorf("the dry run killed the victim session: %v", err)
	}
	var next int
	if err := rw.QueryRow("SELECT nextval('komando_seq2')").Scan(&next); err != nil || next != 1 {
		t.Errorf("the dry run moved the sequence: %d %v", next, err)
	}
}

// More MySQL and MariaDB cases.
func TestTxSafetyMySQLLive2(t *testing.T) {
	ctx := context.Background()
	rw := liveDB(t, "KOMANDO_MYTEST", false, "")
	for _, q := range []string{"DROP TABLE IF EXISTS komando_victim2", "CREATE TABLE komando_victim2 (id int) ENGINE=InnoDB", "INSERT INTO komando_victim2 VALUES (1)"} {
		if _, err := rw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { rw.Exec("DROP TABLE IF EXISTS komando_victim2") })

	// D1: GBK reads \xbf\x5c as one character
	for _, p := range []string{"SET NAMES gbk; SELECT '\xbf\x5c' INTO OUTFILE '/tmp/x' -- '", "SET character_set_client = sjis", "SET CHARACTER SET big5"} {
		if _, err := driver.ClassifySQL("mysql", p); errCode(err) != "SQL_STRING_RULES" {
			t.Errorf("%q: %v", p, err)
		}
	}
	if err := openErr(t, "KOMANDO_MYTEST", "character_set_client=gbk"); errCode(err) != "SQL_STRING_RULES" {
		t.Errorf("GBK connection: %v", err)
	}

	// R2: the server ignores the rest of the line after --\x7f, and so does komando
	plan, err := driver.ClassifySQL("mysql", "SELECT 1 --\x7f '\nINTO OUTFILE '/tmp/komando_zz.txt' -- '")
	if err != nil || !plan.NeedsWrite() {
		t.Errorf("--\\x7f: %+v %v", plan, err)
	}

	// D3: statements that commit implicitly must be sent alone, so the
	// DELETE before them is rolled back
	for _, stmt := range []string{"IMPORT TABLE FROM '/nonexist.sdi'", "CLONE LOCAL DATA DIRECTORY = '/tmp/x'", "BACKUP STAGE START", "XA START 'komando'"} {
		p, err := driver.ClassifySQL("mysql", "DELETE FROM komando_victim2 WHERE id = 1; "+stmt)
		if err == nil {
			_, err = Run(ctx, rw, "mysql", p, Options{Write: true, DryRun: true})
		}
		if err == nil || !strings.Contains(err.Error(), "send it on its own") {
			t.Errorf("%q: %v", stmt, err)
		}
		if n := count(t, rw, "komando_victim2"); n != 1 {
			t.Fatalf("%q: the dry run committed the DELETE (%d rows)", stmt, n)
		}
	}
}
