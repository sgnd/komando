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
)

// These run when KOMANDO_CHTEST (clickhouse://admin@127.0.0.1:PORT/default)
// names a disposable ClickHouse server whose user may manage users, with
// the password in KOMANDO_CHTEST_PASSWORD. They make and drop the
// database komando_ct and the users and roles komando_ct_*.

func liveCH(t *testing.T, user, password string, readOnly bool) (*sql.DB, string) {
	t.Helper()
	u := os.Getenv("KOMANDO_CHTEST")
	if u == "" {
		t.Skip("set KOMANDO_CHTEST to run")
	}
	if user != "" {
		tg, _ := driver.Parse(u)
		u = strings.Replace(u, tg.User+"@", user+"@", 1)
	} else {
		password = os.Getenv("KOMANDO_CHTEST_PASSWORD")
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, password, nil, readOnly, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, u
}

func chLiveRun(t *testing.T, db *sql.DB, write, dry bool, query string, args ...any) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("clickhouse", query)
	if err != nil {
		return nil, err
	}
	return Run(context.Background(), db, "clickhouse", plan, Options{Write: write, DryRun: dry, Limit: 100, Timeout: 60 * time.Second, Args: args})
}

func TestClickHouseLive(t *testing.T) {
	ctx := context.Background()
	admin, _ := liveCH(t, "", "", false)
	for _, q := range []string{"DROP DATABASE IF EXISTS komando_ct", "CREATE DATABASE komando_ct",
		"CREATE TABLE komando_ct.orders (id UInt64, item String, total Decimal(10, 2), placed DateTime DEFAULT now(), " +
			"INDEX item_idx item TYPE bloom_filter GRANULARITY 1) ENGINE = MergeTree ORDER BY id"} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	t.Cleanup(func() { admin.ExecContext(ctx, "DROP DATABASE IF EXISTS komando_ct") })

	// writes need --write, go alone, and a dry run sends nothing
	if _, err := chLiveRun(t, admin, false, false, "insert into komando_ct.orders (id, item, total) values (1, 'pen', 1.5)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert without --write: %v", err)
	}
	res, err := chLiveRun(t, admin, true, true, "insert into komando_ct.orders (id, item, total) values (1, 'pen', 1.5)")
	if err != nil || res.Results[0].Skipped == "" {
		t.Errorf("dry run: %+v %v", res, err)
	}
	res, err = chLiveRun(t, admin, true, false, "insert into komando_ct.orders (id, item, total) values (1, 'pen', 1.5), (2, 'ink', 12.25)")
	if err != nil || *res.Results[0].RowsAffected != 2 {
		t.Fatalf("insert: %+v %v", res, err)
	}
	if _, err := chLiveRun(t, admin, true, false, "insert into komando_ct.orders (id, item) values (3, 'x'); select 1"); errCode(err) != "USAGE" {
		t.Errorf("a write with another statement: %v", err)
	}

	// reads, with placeholders and exact decimals
	ro, _ := liveCH(t, "", "", true)
	res, err = chLiveRun(t, ro, false, false, "select item, total from komando_ct.orders where id = {p1:UInt64}", "2")
	if err != nil || fmt.Sprint(res.Results[0].Rows) != "[[ink 12.25]]" {
		t.Errorf("select: %+v %v", res, err)
	}
	res, err = chLiveRun(t, ro, false, false, "select total from komando_ct.orders where id = 1")
	if err != nil || fmt.Sprint(res.Results[0].Rows) != "[[1.50]]" {
		t.Errorf("decimal: %+v %v", res, err)
	}

	// the server's own read-only layer: SQL that reaches it without the
	// classifier is refused there
	for _, q := range []string{"INSERT INTO komando_ct.orders (id) VALUES (9)", "DROP TABLE komando_ct.orders", "SET max_threads = 1"} {
		if _, err := ro.ExecContext(ctx, q); chCode(err) != 164 {
			t.Errorf("read-only connection, %s: %v", q, err)
		}
	}
	if _, err := admin.QueryContext(ctx, "INSERT INTO komando_ct.orders (id) SELECT 9"); err == nil {
		t.Error("a query (rows) carries readonly=1 even on a connection that may write")
	}

	// a failure after the first rows
	plan, _ := driver.ClassifySQL("clickhouse", "select number, throwIf(number = 150000) from numbers(200000)")
	if _, err := Run(ctx, ro, "clickhouse", plan, Options{Timeout: time.Minute}); errCode(err) != "DB_ERROR" || !strings.Contains(err.Error(), "throwIf") {
		t.Errorf("failure mid-stream: %v", err)
	}

	// schema, info, sizes
	tables, err := Schema(ctx, ro, "clickhouse", []string{"komando_ct.orders"}, 30*time.Second)
	if err != nil || len(tables) != 1 || tables[0].Engine != "MergeTree" || len(tables[0].Columns) != 4 || !tables[0].Columns[0].PrimaryKey {
		t.Fatalf("schema: %+v %v", tables, err)
	}
	if d := tables[0].Columns[3].Default; d == nil || *d != "now()" {
		t.Errorf("default: %v", d)
	}
	if fmt.Sprint(tables[0].Indexes) == "" || !strings.Contains(fmt.Sprint(tables[0].Indexes), "bloom_filter") {
		t.Errorf("indexes: %+v", tables[0].Indexes)
	}
	info, err := Info(ctx, ro, "clickhouse", 30*time.Second)
	if err != nil || info["version"] == nil || info["uptime_seconds"] == nil {
		t.Errorf("info: %v %v", info, err)
	}
	sizes, err := Sizes(ctx, ro, "clickhouse", 50, 30*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(sizes["tables"]), "orders") {
		t.Errorf("sizes: %v %v", sizes, err)
	}

	// a running query shows in activity, and kill stops it
	done := make(chan error, 1)
	go func() {
		_, err := chLiveRun(t, ro, false, false, "select count() from numbers(100000000000)")
		done <- err
	}()
	var pid int64
	for i := 0; i < 100 && pid == 0; i++ {
		time.Sleep(100 * time.Millisecond)
		rows, err := Activity(ctx, admin, "clickhouse", false, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if strings.Contains(fmt.Sprint(r["query"]), "numbers(100000000000)") {
				pid, _ = r["pid"].(int64)
			}
		}
	}
	if pid == 0 {
		t.Fatal("the running query is not in db activity")
	}
	if err := Kill(ctx, admin, "clickhouse", pid, true); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("kill --session: %v", err)
	}
	if err := Kill(ctx, admin, "clickhouse", pid, false); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if errCode(err) != "DB_ERROR" {
			t.Errorf("the killed query: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Error("the query did not stop")
	}
}

func TestClickHouseUsersLive(t *testing.T) {
	ctx := context.Background()
	admin, _ := liveCH(t, "", "", false)
	for _, q := range []string{"DROP USER IF EXISTS komando_ct_ro", "DROP ROLE IF EXISTS komando_ct_readers",
		"CREATE DATABASE IF NOT EXISTS komando_ct", "CREATE TABLE IF NOT EXISTS komando_ct.t (a UInt8) ENGINE = Memory"} {
		if _, err := admin.ExecContext(ctx, q); err != nil {
			t.Fatal(q, err)
		}
	}
	t.Cleanup(func() {
		admin.ExecContext(ctx, "DROP USER IF EXISTS komando_ct_ro")
		admin.ExecContext(ctx, "DROP ROLE IF EXISTS komando_ct_readers")
		admin.ExecContext(ctx, "DROP DATABASE IF EXISTS komando_ct")
	})
	shown, err := UserChange(ctx, admin, "clickhouse", "add", UserSpec{Name: "komando_ct_ro", Password: "Ro-pass-1x"}, false)
	if err != nil || strings.Contains(shown, "Ro-pass") || !strings.Contains(shown, "[hidden]") {
		t.Fatalf("user add: %s %v", shown, err)
	}
	if _, err := UserChange(ctx, admin, "clickhouse", "add", UserSpec{Name: "komando_ct_ro", Password: "x"}, false); errCode(err) != "DB_USER_EXISTS" {
		t.Errorf("add twice: %v", err)
	}
	if _, err := UserChange(ctx, admin, "clickhouse", "add", UserSpec{Name: "komando_ct_readers", NoLogin: true}, false); err != nil {
		t.Fatal(err)
	}
	for _, g := range []Grant{{User: "komando_ct_readers", Privs: []string{"SELECT"}, On: "komando_ct.*"},
		{User: "komando_ct_ro", Role: "komando_ct_readers"}} {
		stmt, err := GrantSQL(ctx, admin, "clickhouse", g)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatal(stmt, err)
		}
	}
	if _, err := admin.ExecContext(ctx, "SET DEFAULT ROLE ALL TO komando_ct_ro"); err != nil {
		t.Fatal(err)
	}
	grants, err := Grants(ctx, admin, "clickhouse", "komando_ct_ro", "", 30*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(grants), "komando_ct_readers") {
		t.Errorf("grants: %v %v", grants, err)
	}
	grants, err = Grants(ctx, admin, "clickhouse", "komando_ct_readers", "", 30*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(grants), "komando_ct.*") {
		t.Errorf("role grants: %v %v", grants, err)
	}
	// the new user logs in with the password komando hashed
	user, _ := liveCH(t, "komando_ct_ro", "Ro-pass-1x", true)
	if _, err := chLiveRun(t, user, false, false, "select count() from komando_ct.t"); err != nil {
		t.Errorf("the new user reads: %v", err)
	}
	if _, err := UserChange(ctx, admin, "clickhouse", "passwd", UserSpec{Name: "komando_ct_ro", Password: "Ro-pass-2x"}, false); err != nil {
		t.Fatal(err)
	}
	liveCH(t, "komando_ct_ro", "Ro-pass-2x", true)
	users, err := Users(ctx, admin, "clickhouse", 30*time.Second)
	if err != nil || !strings.Contains(fmt.Sprint(users), "komando_ct_readers") {
		t.Errorf("user ls: %v %v", users, err)
	}
	for _, name := range []string{"komando_ct_ro", "komando_ct_readers"} {
		if s, err := UserChange(ctx, admin, "clickhouse", "rm", UserSpec{Name: name}, false); err != nil {
			t.Errorf("rm %s (%s): %v", name, s, err)
		}
	}
	if _, err := UserChange(ctx, admin, "clickhouse", "rm", UserSpec{Name: "komando_ct_ro"}, false); errCode(err) != "DB_USER_NOT_FOUND" {
		t.Errorf("rm twice: %v", err)
	}
}

// --via: the dialer gets the name, as an SSH server would.
func TestClickHouseViaLive(t *testing.T) {
	u := os.Getenv("KOMANDO_CHTEST")
	if u == "" {
		t.Skip("set KOMANDO_CHTEST to run")
	}
	tg, _ := driver.Parse(u)
	host, port, _ := net.SplitHostPort(tg.Address)
	raw := strings.Replace(u, host+":"+port, "clickhouse.invalid:"+port, 1)
	via, _ := driver.Parse(raw)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "clickhouse.invalid:"+port {
			return nil, fmt.Errorf("dialed %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, tg.Address)
	}
	db, err := Open(context.Background(), raw, via, os.Getenv("KOMANDO_CHTEST_PASSWORD"), dial, true, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := chLiveRun(t, db, false, false, "select 1"); err != nil {
		t.Error(err)
	}
}
