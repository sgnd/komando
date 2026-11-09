package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// These run when KOMANDO_ORATEST (oracle://system@127.0.0.1:PORT/FREEPDB1)
// names a disposable Oracle database, with the password in
// KOMANDO_ORATEST_PASSWORD. They make and drop the users KOMANDO_OT and
// KOMANDO_RO.

func liveOra(t *testing.T, user, password string) *sql.DB {
	t.Helper()
	u := os.Getenv("KOMANDO_ORATEST")
	if u == "" {
		t.Skip("set KOMANDO_ORATEST to run")
	}
	if user != "" {
		u = strings.Replace(u, "system@", user+"@", 1)
	} else {
		password = os.Getenv("KOMANDO_ORATEST_PASSWORD")
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, password, nil, false, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func oraRun(t *testing.T, db *sql.DB, write, dry bool, query string, args ...any) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("oracle", query)
	if err != nil {
		return nil, err
	}
	return Run(context.Background(), db, "oracle", plan, Options{Write: write, DryRun: dry, Limit: 100, Timeout: 60 * time.Second, Args: args})
}

func oraCode(err error) string {
	if e, ok := err.(*out.Error); ok {
		return e.Code
	}
	return fmt.Sprint(err)
}

func TestOracleLive(t *testing.T) {
	ctx := context.Background()
	sys := liveOra(t, "", "")
	for _, q := range []string{`begin execute immediate 'drop user komando_ot cascade'; exception when others then null; end;`,
		`begin execute immediate 'drop user komando_ro cascade'; exception when others then null; end;`} {
		if _, err := sys.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`create user komando_ot identified by "Ot-pass-1x" quota unlimited on users`,
		`grant create session, create table, create sequence, create procedure to komando_ot`,
	} {
		if _, err := sys.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	defer sys.ExecContext(ctx, "drop user komando_ot cascade")
	db := liveOra(t, "komando_ot", "Ot-pass-1x")
	for _, q := range []string{
		"create table orders (id number generated always as identity primary key, item varchar2(50 char) not null, total number(10,2), qty number, b raw(10), placed date default sysdate, ts timestamp, c clob, constraint ck_total check (total >= 0))",
		"create index ix_item on orders (item desc)",
		"create table lines (id number primary key, order_id number references orders(id) on delete cascade, n number check (n > 0))",
		"create or replace function bump return number is pragma autonomous_transaction; begin insert into orders (item) values ('sneaky'); commit; return 1; end;\n/",
	} {
		if _, err := oraRun(t, db, true, false, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := oraRun(t, db, true, false, "insert into orders (item, total, qty, b, placed, ts, c) values ('pen', 1.50, 3, hextoraw('616263'), date '2026-11-09', timestamp '2026-11-09 13:04:05.12', 'long text')"); err != nil {
		t.Fatal(err)
	}
	if _, err := oraRun(t, db, true, false, "insert into orders (item, total) values (:1, :2)", "ink", "12.25"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second) // a read-only transaction right after the DDL may say ORA-01466
	res, err := oraRun(t, db, false, false, "select item, total, qty, b, placed, ts, c from orders where id = :1", "1")
	if err != nil {
		t.Fatal(err)
	}
	row := res.Results[0].Rows[0]
	t.Logf("columns %+v row %#v", res.Results[0].Columns, row)
	if row[0] != "pen" || row[1] != 1.5 || row[2] != int64(3) || fmt.Sprint(row[3]) != "map[base64:YWJj]" ||
		row[4] != "2026-11-09 00:00:00" || row[5] != "2026-11-09 13:04:05.12" || row[6] != "long text" {
		t.Errorf("values: %#v", row)
	}

	count := func() any {
		r, err := oraRun(t, db, false, false, "select count(*) from orders")
		if err != nil {
			t.Fatal(err)
		}
		return r.Results[0].Rows[0][0]
	}
	// a dry run counts and rolls back
	res, err = oraRun(t, db, true, true, "delete from orders where id > 0")
	if err != nil || *res.Results[0].RowsAffected != 2 || !res.RolledBack {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if n := fmt.Sprint(count()); n != "2" {
		t.Errorf("after the dry run: %v rows", n)
	}
	// the read-only transaction refuses a write the classifier missed
	sneaky := driver.SQLPlan{Statements: []driver.Statement{{SQL: "delete from orders", Keyword: "SELECT", Risk: driver.RiskRead}}}
	if _, err := Run(ctx, db, "oracle", sneaky, Options{Timeout: 10 * time.Second}); oraCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("a write in a read run: %v", err)
	}
	// a COMMIT that gets past the classifier stops the run before the next statement
	commit := driver.SQLPlan{Statements: []driver.Statement{
		{SQL: "commit", Keyword: "SELECT", Risk: driver.RiskRead},
		{SQL: "delete from orders", Keyword: "SELECT", Risk: driver.RiskRead},
	}}
	if _, err := Run(ctx, db, "oracle", commit, Options{Timeout: 10 * time.Second}); oraCode(err) != "SQL_TX_CONTROL" {
		t.Errorf("a hidden commit: %v", err)
	}
	commitW := driver.SQLPlan{Statements: []driver.Statement{
		{SQL: "update orders set qty = 9 where id = 1", Keyword: "UPDATE", Risk: driver.RiskWrite},
		{SQL: "commit", Keyword: "SELECT", Risk: driver.RiskRead},
		{SQL: "delete from orders", Keyword: "DELETE", Risk: driver.RiskWrite},
	}}
	if _, err := Run(ctx, db, "oracle", commitW, Options{Write: true, DryRun: true, Timeout: 10 * time.Second}); oraCode(err) != "SQL_TX_CONTROL" {
		t.Errorf("a hidden commit in a dry run: %v", err)
	}
	if n := fmt.Sprint(count()); n != "2" {
		t.Errorf("after the hidden commits: %v rows", n)
	}
	// a function with its own transaction (PRAGMA AUTONOMOUS_TRANSACTION)
	// commits even in a read-only transaction: the documented limit
	if _, err := oraRun(t, db, false, false, "select bump from dual"); err != nil {
		t.Errorf("autonomous function in a read run: %v", err)
	}
	if n := fmt.Sprint(count()); n != "3" {
		t.Errorf("after the autonomous function: %v rows", n)
	}
	// ddl needs --write and goes alone
	if _, err := oraRun(t, db, false, false, "create table x (a number)"); oraCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("ddl without --write: %v", err)
	}
	if res, err := oraRun(t, db, true, true, "create table x (a number)"); err != nil || res.Results[0].Skipped == "" {
		t.Errorf("ddl in a dry run: %+v %v", res, err)
	}
	if _, err := oraRun(t, db, true, false, "insert into orders (item) values ('a'); create table x (a number)"); err == nil {
		t.Error("ddl with another statement")
	}
	// a PL/SQL block: --write only, and not in a dry run
	if _, err := oraRun(t, db, false, false, "begin null; end;"); oraCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("block without --write: %v", err)
	}
	if _, err := oraRun(t, db, true, false, "begin insert into orders (item) values ('blk'); end;\n/"); err != nil {
		t.Errorf("block: %v", err)
	}
	if _, err := oraRun(t, db, false, false, "select :1, :2 from dual", "x"); oraCode(err) != "USAGE" {
		t.Errorf("args: %v", err)
	}

	// explain: the plan, nothing runs
	plan, _ := driver.ClassifySQL("oracle", "delete from orders where id = 1")
	res, err = Run(ctx, db, "oracle", driver.PlanOnly(plan), Options{Timeout: 10 * time.Second, Showplan: "text"})
	if err != nil || !strings.Contains(fmt.Sprint(res.Results[0].Rows), "DELETE STATEMENT") {
		t.Fatalf("explain: %+v %v", res, err)
	}
	if n := fmt.Sprint(count()); n != "4" {
		t.Errorf("explain ran the delete: %v rows", n)
	}
	plan, _ = driver.ClassifySQL("oracle", "select * from orders where id = :1")
	if res, err = Run(ctx, db, "oracle", plan, Options{Timeout: 10 * time.Second, Showplan: "text"}); err != nil || !strings.Contains(fmt.Sprint(res.Results[0].Rows), "INDEX UNIQUE SCAN") {
		t.Errorf("explain with a bind: %+v %v", res, err)
	}

	// schema
	tables, err := Schema(ctx, db, "oracle", nil, 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(tables), "KOMANDO_OT ORDERS table") {
		t.Fatalf("schema: %+v %v", tables, err)
	}
	tables, err = Schema(ctx, db, "oracle", []string{"komando_ot.orders", "lines"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o, l := tables[0], tables[1]
	t.Logf("orders %+v", o)
	if o.Columns[0].Identity != "always" || !o.Columns[0].PrimaryKey || o.Columns[1].Type != "VARCHAR2(50 CHAR)" || o.Columns[1].Nullable ||
		o.Columns[2].Type != "NUMBER(10,2)" || o.Columns[5].Default == nil || len(o.Indexes) != 2 {
		t.Errorf("orders: %+v", o)
	}
	if !strings.Contains(fmt.Sprint(o.Constraints), "CHECK (total >= 0)") {
		t.Errorf("orders constraints: %+v", o.Constraints)
	}
	if !strings.Contains(fmt.Sprint(l.Constraints), "REFERENCES KOMANDO_OT.ORDERS(ID) ON DELETE CASCADE") {
		t.Errorf("constraints: %+v", l.Constraints)
	}

	// the DBA views, as system
	info, err := Info(ctx, sys, "oracle", 10*time.Second)
	if err != nil || info["role"] != "primary" || info["database"] != "FREEPDB1" || info["uptime_seconds"] == nil {
		t.Errorf("info: %v %v", info, err)
	}
	if info, err := Info(ctx, db, "oracle", 10*time.Second); err != nil || info["version"] == nil {
		t.Errorf("info as a plain user: %v %v", info, err)
	}
	if _, err := Activity(ctx, sys, "oracle", true, 10*time.Second); err != nil {
		t.Errorf("activity: %v", err)
	}
	if _, err := Activity(ctx, db, "oracle", true, 10*time.Second); oraCode(err) != "DB_PRIVILEGE" {
		t.Errorf("activity as a plain user: %v", err)
	}
	if _, err := Locks(ctx, sys, "oracle", 10*time.Second); err != nil {
		t.Errorf("locks: %v", err)
	}
	for _, c := range []*sql.DB{sys, db} {
		sizes, err := Sizes(ctx, c, "oracle", 5, 10*time.Second)
		if err != nil || !strings.Contains(fmt.Sprint(sizes["tables"]), "ORDERS") || !strings.Contains(fmt.Sprint(sizes["indexes"]), "IX_ITEM") {
			t.Errorf("sizes: %v %v", sizes, err)
		}
	}

	// users and grants
	u := UserSpec{Name: "komando_ro", Password: "Ro-pass-1x'"}
	if _, err := UserChange(ctx, sys, "oracle", "add", u, false); err != nil {
		t.Fatal(err)
	}
	defer UserChange(ctx, sys, "oracle", "rm", u, false)
	if _, err := UserChange(ctx, sys, "oracle", "add", u, false); oraCode(err) != "DB_USER_EXISTS" {
		t.Errorf("add twice: %v", err)
	}
	for _, g := range []Grant{{User: "komando_ro", Privs: []string{"SELECT"}, On: "table:komando_ot.orders"}, {User: "komando_ro", Role: "select_catalog_role"},
		{User: "komando_ro", Privs: []string{"select"}, On: "schema:komando_ot"}} {
		s, err := GrantSQL(ctx, sys, "oracle", g)
		if err == nil {
			_, err = sys.ExecContext(ctx, s)
		}
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	grants, err := Grants(ctx, sys, "oracle", "komando_ro", "", 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(grants), "object:KOMANDO_OT.ORDERS on_type:table privileges:SELECT") ||
		!strings.Contains(fmt.Sprint(grants), "SELECT_CATALOG_ROLE") || !strings.Contains(fmt.Sprint(grants), "CREATE SESSION") {
		t.Errorf("grants: %v %v", grants, err)
	}
	t.Logf("grants %v", grants)
	users, err := Users(ctx, sys, "oracle", 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(users), "KOMANDO_RO") {
		t.Errorf("users: %v %v", users, err)
	}
	rdb := liveOra(t, "komando_ro", u.Password)
	if _, err := oraRun(t, rdb, true, false, "insert into komando_ot.orders (item) values ('x')"); err == nil {
		t.Error("the read-only user wrote")
	}
	if _, err := UserChange(ctx, sys, "oracle", "rm", u, false); oraCode(err) != "DB_USER_IN_USE" {
		t.Errorf("rm while logged in: %v", err)
	}
	rdb.Close()
	if _, err := UserChange(ctx, sys, "oracle", "passwd", UserSpec{Name: "komando_ro", Password: "Ro-pass-2y"}, false); err != nil {
		t.Errorf("passwd: %v", err)
	}
	if _, err := UserChange(ctx, sys, "oracle", "rm", u, false); err != nil {
		t.Errorf("rm: %v", err)
	}
	if _, err := UserChange(ctx, sys, "oracle", "rm", u, false); oraCode(err) != "DB_USER_NOT_FOUND" {
		t.Errorf("rm twice: %v", err)
	}
	ro := strings.Replace(os.Getenv("KOMANDO_ORATEST"), "system@", "komando_ot@", 1)
	tg, _ := driver.Parse(ro)
	if _, err := Open(ctx, ro, tg, "wrong", nil, true, "k"); oraCode(err) != "DB_AUTH" {
		t.Errorf("a wrong password: %v", err)
	}
	bad := strings.Replace(ro, "FREEPDB1", "NOPE", 1)
	tg, _ = driver.Parse(bad)
	if _, err := Open(ctx, bad, tg, "x", nil, true, "k"); oraCode(err) != "DB_NOT_FOUND" {
		t.Errorf("a wrong service: %v", err)
	}
	// kill a session of komando_ot
	victim := liveOra(t, "komando_ot", "Ot-pass-1x")
	var sid int64
	if err := victim.QueryRowContext(ctx, "select sys_context('userenv', 'sid') from dual").Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if err := Kill(ctx, sys, "oracle", sid, false); err != nil {
		t.Errorf("cancel: %v", err)
	}
	if err := Kill(ctx, sys, "oracle", sid, true); err != nil {
		t.Errorf("kill: %v", err)
	}
	if err := Kill(ctx, sys, "oracle", 999999, false); oraCode(err) != "SESSION_NOT_FOUND" {
		t.Errorf("kill a missing session: %v", err)
	}
}

// Through --via the driver hands the host name to komando's dial, which
// the SSH server resolves: here a name only the dial knows.
func TestOracleLiveVia(t *testing.T) {
	u := os.Getenv("KOMANDO_ORATEST")
	if u == "" {
		t.Skip("set KOMANDO_ORATEST to run")
	}
	tg, _ := driver.Parse(u)
	real := tg.Address
	_, port, _ := net.SplitHostPort(real)
	via := strings.Replace(u, real, "oracle.invalid:"+port, 1)
	tg, err := driver.Parse(via)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		return (&net.Dialer{}).DialContext(ctx, network, real)
	}
	db, err := Open(context.Background(), via, tg, os.Getenv("KOMANDO_ORATEST_PASSWORD"), dial, true, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(asked) == 0 || asked[0] != "oracle.invalid:"+port {
		t.Errorf("dialed %v", asked)
	}
}
