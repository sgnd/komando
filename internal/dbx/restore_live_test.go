package dbx

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// Live dump/restore regressions. They run when KOMANDO_PGTEST (a
// postgres:// URL) or KOMANDO_MYTEST (a mysql:// URL) names a server where
// the user may create databases; the passwords are in
// KOMANDO_PGTEST_PASSWORD and KOMANDO_MYTEST_PASSWORD.

func liveOpen(t *testing.T, env, dbName string) *sql.DB {
	t.Helper()
	base := os.Getenv(env)
	if base == "" {
		t.Skipf("set %s to run", env)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if dbName != "" {
		u.Path = "/" + dbName
	}
	tg, err := driver.Parse(u.String())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u.String(), tg, os.Getenv(env+"_PASSWORD"), nil, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func liveExec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := db.ExecContext(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// dumpCheckRestore dumps src, checks the file and restores it into dst.
func dumpCheckRestore(t *testing.T, kind string, src, dst *sql.DB, o DumpOptions) string {
	t.Helper()
	ctx := context.Background()
	var buf bytes.Buffer
	if err := Dump(ctx, src, kind, o, &buf); err != nil {
		t.Fatalf("dump: %v", err)
	}
	v, err := driver.CheckRestore(kind, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("check: %v\n%s", err, buf.String())
	}
	if len(v.RuleIDs) > 0 { // komando's own dump only creates and fills objects
		t.Errorf("check names %v in komando's own dump: %v", v.RuleIDs, v.Reasons)
	}
	if err := Restore(ctx, dst, kind, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("restore: %v\n%s", err, buf.String())
	}
	return buf.String()
}

func liveOne(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	var s sql.NullString
	if err := db.QueryRowContext(context.Background(), q).Scan(&s); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return s.String
}

// TestPgDumpNamesAndTablesLive: names with dots (D9), --table with a
// standalone sequence and no extra tables (D8), and SQL-standard function
// bodies the restore must not split (D13).
func TestPgDumpNamesAndTablesLive(t *testing.T) {
	admin := liveOpen(t, "KOMANDO_PGTEST", "")
	for _, d := range []string{"kfix_src", "kfix_all", "kfix_one"} {
		liveExec(t, admin, "DROP DATABASE IF EXISTS "+d, "CREATE DATABASE "+d)
	}
	src := liveOpen(t, "KOMANDO_PGTEST", "kfix_src")
	liveExec(t, src, `CREATE SCHEMA d9;
CREATE TABLE d9."order.items" (id serial PRIMARY KEY, v text);
CREATE TABLE d9.t ("a.b" serial, v text);
CREATE TABLE d9.x (y int);
CREATE TABLE d9."x.y" (id serial);
CREATE SCHEMA "my.schema";
CREATE TABLE "my.schema".ev (id int, at date) PARTITION BY RANGE (at);
CREATE TABLE "my.schema".ev_2026 PARTITION OF "my.schema".ev FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
INSERT INTO "my.schema".ev VALUES (1, '2026-02-02');
CREATE SEQUENCE public.order_no START 1000;
CREATE TABLE public.orders (id int PRIMARY KEY DEFAULT nextval('public.order_no'), item text);
CREATE TABLE public.zz_later (id int);
INSERT INTO public.orders (item) VALUES ('a'), ('b');
INSERT INTO d9."order.items" (v) VALUES ('x');
CREATE FUNCTION public.two() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; SELECT 2; END;`)

	all := liveOpen(t, "KOMANDO_PGTEST", "kfix_all")
	dumpCheckRestore(t, "postgres", src, all, DumpOptions{})
	for q, want := range map[string]string{
		`SELECT pg_get_serial_sequence('d9."order.items"', 'id')`:      `d9."order.items_id_seq"`,
		`SELECT pg_get_serial_sequence('d9.t', 'a.b')`:                 `d9."t_a.b_seq"`,
		`SELECT pg_get_serial_sequence('d9."x.y"', 'id')`:              `d9."x.y_id_seq"`,
		`SELECT COALESCE(pg_get_serial_sequence('d9.x', 'y'), 'none')`: "none",
		`SELECT count(*)::text FROM "my.schema".ev`:                    "1",
		`SELECT public.two()::text`:                                    "2",
	} {
		if got := liveOne(t, all, q); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}

	one := liveOpen(t, "KOMANDO_PGTEST", "kfix_one")
	dump := dumpCheckRestore(t, "postgres", src, one, DumpOptions{Tables: []string{"public.orders"}})
	for _, bad := range []string{"zz_later", "x.y_id_seq", "order.items"} {
		if strings.Contains(dump, bad) {
			t.Errorf("--table public.orders dump contains %s", bad)
		}
	}
	liveExec(t, one, "INSERT INTO public.orders (item) VALUES ('c')")
	if got := liveOne(t, one, "SELECT max(id)::text FROM public.orders"); got != "1002" {
		t.Errorf("the sequence position did not come back: max id %s", got)
	}
	var buf bytes.Buffer
	if err := Dump(context.Background(), src, "postgres", DumpOptions{Tables: []string{`d9."x.y"`}}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `CREATE TABLE "d9"."x.y"`) || strings.Contains(buf.String(), `CREATE TABLE "d9"."x"`) {
		t.Errorf("--table d9.\"x.y\" picked the wrong tables:\n%s", buf.String())
	}
}

// TestMySQLDumpGeneratedAndViewsLive: generated columns are left out of the
// INSERTs (D6), and views that read other views or call functions restore
// into an empty database whatever their names (D7).
func TestMySQLDumpGeneratedAndViewsLive(t *testing.T) {
	src := liveOpen(t, "KOMANDO_MYTEST", "")
	liveExec(t, src, "DROP DATABASE IF EXISTS kfix_copy", "CREATE DATABASE kfix_copy",
		"DROP VIEW IF EXISTS a_v", "DROP VIEW IF EXISTS b_v", "DROP VIEW IF EXISTS c_v", "DROP TABLE IF EXISTS g", "DROP FUNCTION IF EXISTS dbl",
		"CREATE TABLE g (id INT PRIMARY KEY, price INT, qty INT, total INT AS (price*qty) VIRTUAL, label VARCHAR(20) AS (CONCAT('x',id)) STORED, made DATETIME DEFAULT (NOW()))",
		"INSERT INTO g (id, price, qty, made) VALUES (1, 3, 4, '2020-01-02 03:04:05'), (2, 5, 6, NULL)",
		"CREATE FUNCTION dbl(x INT) RETURNS INT DETERMINISTIC RETURN x*2",
		"CREATE VIEW b_v AS SELECT id, total FROM g",
		"CREATE VIEW a_v AS SELECT id FROM b_v WHERE id > 1",
		"CREATE VIEW c_v AS SELECT dbl(id) AS d FROM g")
	dst := liveOpen(t, "KOMANDO_MYTEST", "kfix_copy")
	dumpCheckRestore(t, "mysql", src, dst, DumpOptions{})
	for q, want := range map[string]string{
		"SELECT GROUP_CONCAT(CONCAT(id, ':', total, ':', label, ':', IFNULL(made, 'null')) ORDER BY id) FROM g": "1:12:x1:2020-01-02 03:04:05,2:30:x2:null",
		"SELECT GROUP_CONCAT(id) FROM a_v":           "2",
		"SELECT GROUP_CONCAT(d ORDER BY d) FROM c_v": "2,4",
	} {
		if got := liveOne(t, dst, q); got != want {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
}
