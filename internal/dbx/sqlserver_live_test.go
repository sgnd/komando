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

// These run when KOMANDO_MSTEST (sqlserver://sa@127.0.0.1:PORT/master)
// names a disposable SQL Server, with the password in
// KOMANDO_MSTEST_PASSWORD. They make and drop the database komando_mstest.

func liveMS(t *testing.T, database string, readOnly bool) *sql.DB {
	t.Helper()
	u := os.Getenv("KOMANDO_MSTEST")
	if u == "" {
		t.Skip("set KOMANDO_MSTEST to run")
	}
	if database != "" {
		u = u[:strings.LastIndex(u, "/")+1] + database
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, os.Getenv("KOMANDO_MSTEST_PASSWORD"), nil, readOnly, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func msRun(t *testing.T, db *sql.DB, write, dry bool, query string, args ...any) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("sqlserver", query)
	if err != nil {
		return nil, err
	}
	return Run(context.Background(), db, "sqlserver", plan, Options{Write: write, DryRun: dry, Limit: 100, Timeout: 30 * time.Second, Args: args})
}

func TestSQLServerLive(t *testing.T) {
	ctx := context.Background()
	master := liveMS(t, "", false)
	if _, err := msRun(t, master, true, false, "drop database if exists komando_mstest"); err != nil {
		t.Fatal(err)
	}
	if _, err := msRun(t, master, true, false, "create database komando_mstest"); err != nil {
		t.Fatal(err)
	}
	defer master.ExecContext(ctx, "drop database komando_mstest")
	db := liveMS(t, "komando_mstest", false)
	for _, q := range []string{
		"create table dbo.orders (id int identity primary key, item nvarchar(50) not null, total decimal(10,2), g uniqueidentifier default newid(), b varbinary(10), placed datetime2 default sysdatetime(), d date, tm time)",
		"create index ix_item on dbo.orders (item desc)",
		"create table dbo.lines (id int primary key, order_id int references dbo.orders(id) on delete cascade, n int check (n > 0))",
		"insert into dbo.orders (item, total, b, d, tm) values (N'pen', 1.50, 0x616263, '2026-11-09', '13:04:05.12'), (N'ink', 12.25, null, null, null)",
	} {
		if _, err := msRun(t, db, true, false, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	res, err := msRun(t, db, false, false, "select item, total, g, b, d, tm from dbo.orders where id = @p1", "1")
	if err != nil {
		t.Fatal(err)
	}
	row := res.Results[0].Rows[0]
	if row[0] != "pen" || row[1] != "1.50" || len(fmt.Sprint(row[2])) != 36 || fmt.Sprint(row[3]) != "map[base64:YWJj]" || row[4] != "2026-11-09" || row[5] != "13:04:05.12" {
		t.Errorf("values: %v %+v", row, res.Results[0].Columns)
	}

	// a dry run counts and rolls back
	res, err = msRun(t, db, true, true, "delete from dbo.orders where id > 0")
	if err != nil || *res.Results[0].RowsAffected != 2 || !res.RolledBack {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	count := func() any {
		r, err := msRun(t, db, false, false, "select count(*) from dbo.orders")
		if err != nil {
			t.Fatal(err)
		}
		return r.Results[0].Rows[0][0]
	}
	if n := count(); n != int64(2) {
		t.Errorf("after the dry run: %v rows", n)
	}

	// a read run is rolled back even when a write gets past the classifier
	sneaky := driver.SQLPlan{Statements: []driver.Statement{{SQL: "delete from dbo.orders", Keyword: "SELECT", Risk: driver.RiskRead}}}
	if _, err := Run(ctx, db, "sqlserver", sneaky, Options{Timeout: 10 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != int64(2) {
		t.Errorf("a read run changed data: %v rows", n)
	}
	// and a COMMIT that gets past it stops the run before the next statement
	commit := driver.SQLPlan{Statements: []driver.Statement{
		{SQL: "commit", Keyword: "SELECT", Risk: driver.RiskRead},
		{SQL: "delete from dbo.orders", Keyword: "SELECT", Risk: driver.RiskRead},
	}}
	if _, err := Run(ctx, db, "sqlserver", commit, Options{Timeout: 10 * time.Second}); err == nil || err.(*out.Error).Code != "SQL_TX_CONTROL" {
		t.Errorf("a hidden commit: %v", err)
	}
	if n := count(); n != int64(2) {
		t.Errorf("after a hidden commit: %v rows", n)
	}
	// a wrong number of --arg values
	if _, err := msRun(t, db, false, false, "select @p1, @p2", "x"); err == nil || err.(*out.Error).Code != "USAGE" {
		t.Errorf("args: %v", err)
	}

	// explain: the plan, nothing runs; --analyze measures
	plan, _ := driver.ClassifySQL("sqlserver", "delete from dbo.orders where id = 1")
	res, err = Run(ctx, db, "sqlserver", driver.PlanOnly(plan), Options{Timeout: 10 * time.Second, Showplan: "text"})
	if err != nil || len(res.Results[0].Rows) == 0 || !strings.Contains(fmt.Sprint(res.Results[0].Rows), "Delete") {
		t.Fatalf("showplan: %+v %v", res, err)
	}
	if n := count(); n != int64(2) {
		t.Errorf("showplan ran the delete: %v rows", n)
	}
	plan, _ = driver.ClassifySQL("sqlserver", "select * from dbo.orders")
	res, err = Run(ctx, db, "sqlserver", plan, Options{Timeout: 10 * time.Second, Showplan: "profile"})
	if err != nil || len(res.Results[0].Rows) == 0 || res.Results[0].Rows[0][0] != int64(2) {
		t.Fatalf("profile: %+v %v", res, err)
	}

	// schema
	tables, err := Schema(ctx, db, "sqlserver", nil, 10*time.Second)
	if err != nil || len(tables) != 2 || tables[1].Schema != "dbo" || tables[1].Name != "orders" || *tables[1].RowEstimate != 2 {
		t.Fatalf("schema: %+v %v", tables, err)
	}
	tables, err = Schema(ctx, db, "sqlserver", []string{"dbo.orders", "lines"}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o, l := tables[0], tables[1]
	if o.Columns[0].Identity != "identity" || !o.Columns[0].PrimaryKey || o.Columns[1].Type != "nvarchar(50)" || o.Columns[1].Nullable ||
		o.Columns[2].Type != "decimal(10,2)" || o.Columns[3].Default == nil || len(o.Indexes) != 2 {
		t.Errorf("orders: %+v", o)
	}
	if !strings.Contains(fmt.Sprint(o.Indexes), "NONCLUSTERED INDEX ix_item (item DESC)") {
		t.Errorf("indexes: %+v", o.Indexes)
	}
	if len(l.Constraints) != 2 || !strings.Contains(l.Constraints[1].Definition, "REFERENCES dbo.orders(id) ON DELETE CASCADE") {
		t.Errorf("constraints: %+v", l.Constraints)
	}

	// the DBA views
	info, err := Info(ctx, db, "sqlserver", 10*time.Second)
	if err != nil || info["role"] != "primary" || info["database"] != "komando_mstest" || info["uptime_seconds"] == nil {
		t.Errorf("info: %v %v", info, err)
	}
	if _, err := Activity(ctx, db, "sqlserver", true, 10*time.Second); err != nil {
		t.Errorf("activity: %v", err)
	}
	if _, err := Locks(ctx, db, "sqlserver", 10*time.Second); err != nil {
		t.Errorf("locks: %v", err)
	}
	sizes, err := Sizes(ctx, db, "sqlserver", 5, 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(sizes["tables"]), "orders") || !strings.Contains(fmt.Sprint(sizes["indexes"]), "ix_item") {
		t.Errorf("sizes: %v %v", sizes, err)
	}

	// users and grants
	u := UserSpec{Name: "komando_ro", Password: "Ro-pass-1x'"}
	if _, err := UserChange(ctx, db, "sqlserver", "add", u, false); err != nil {
		t.Fatal(err)
	}
	defer UserChange(ctx, db, "sqlserver", "rm", u, false)
	if _, err := UserChange(ctx, db, "sqlserver", "add", u, false); err == nil || err.(*out.Error).Code != "DB_USER_EXISTS" {
		t.Errorf("add twice: %v", err)
	}
	for _, g := range []Grant{{User: "komando_ro", Privs: []string{"SELECT"}, On: "schema:dbo"}, {User: "komando_ro", Role: "db_datareader"}} {
		s, err := GrantSQL(ctx, db, "sqlserver", g)
		if err == nil {
			_, err = db.ExecContext(ctx, s)
		}
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	grants, err := Grants(ctx, db, "sqlserver", "komando_ro", "", 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(grants), "object:dbo on_type:schema privileges:SELECT") || !strings.Contains(fmt.Sprint(grants), "db_datareader") {
		t.Errorf("grants: %v %v", grants, err)
	}
	users, err := Users(ctx, db, "sqlserver", 10*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(users), "komando_ro") {
		t.Errorf("users: %v %v", users, err)
	}
	ro := strings.Replace(os.Getenv("KOMANDO_MSTEST"), "sa@", "komando_ro@", 1)
	ro = ro[:strings.LastIndex(ro, "/")+1] + "komando_mstest"
	tg, _ := driver.Parse(ro)
	rdb, err := Open(ctx, ro, tg, u.Password, nil, true, "komando/test")
	if err != nil {
		t.Fatalf("the new user logs in: %v", err)
	}
	if _, err := msRun(t, rdb, true, false, "insert into dbo.orders (item) values (N'x')"); err == nil {
		t.Error("the read-only user wrote")
	}
	if _, err := UserChange(ctx, db, "sqlserver", "rm", u, false); err == nil || err.(*out.Error).Code != "DB_USER_IN_USE" {
		t.Errorf("rm while logged in: %v", err)
	}
	rdb.Close()
	if _, err := UserChange(ctx, db, "sqlserver", "passwd", UserSpec{Name: "komando_ro", Password: "Ro-pass-2y"}, false); err != nil {
		t.Errorf("passwd: %v", err)
	}
	if _, err := UserChange(ctx, db, "sqlserver", "rm", u, false); err != nil {
		t.Errorf("rm: %v", err)
	}
	if _, err := UserChange(ctx, db, "sqlserver", "rm", u, false); err == nil || err.(*out.Error).Code != "DB_USER_NOT_FOUND" {
		t.Errorf("rm twice: %v", err)
	}
	if _, err := Open(ctx, ro, tg, "wrong", nil, true, "k"); err == nil || err.(*out.Error).Code != "DB_AUTH" {
		t.Errorf("a wrong password: %v", err)
	}
}

// Through --via the driver hands the host name to komando's dial, which
// the SSH server resolves: here a name only the dial knows.
func TestSQLServerLiveVia(t *testing.T) {
	u := os.Getenv("KOMANDO_MSTEST")
	if u == "" {
		t.Skip("set KOMANDO_MSTEST to run")
	}
	tg, _ := driver.Parse(u)
	real := tg.Address
	_, port, _ := net.SplitHostPort(real)
	via := strings.Replace(u, real, "mssql.invalid:"+port, 1)
	tg, err := driver.Parse(via)
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		return (&net.Dialer{}).DialContext(ctx, network, real)
	}
	db, err := Open(context.Background(), via, tg, os.Getenv("KOMANDO_MSTEST_PASSWORD"), dial, true, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(asked) == 0 || asked[0] != "mssql.invalid:"+port {
		t.Errorf("dialed %v", asked)
	}
}
