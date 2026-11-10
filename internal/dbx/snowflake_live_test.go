package dbx

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

// These run when KOMANDO_SFTEST names a Snowflake account to test against
// (snowflake://USER@ACCOUNT/DATABASE/SCHEMA?warehouse=W&role=R, a role
// that may create tables in that schema), with KOMANDO_SFTEST_SECRET
// holding a programmatic access token or the user's private key (PEM).
// They make and drop the table KOMANDO_SF_T. No such account was at hand
// when this was written: these tests have not run yet.

func liveSF(t *testing.T, readOnly bool) (*sql.DB, string) {
	t.Helper()
	u := os.Getenv("KOMANDO_SFTEST")
	if u == "" {
		t.Skip("set KOMANDO_SFTEST and KOMANDO_SFTEST_SECRET to run")
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, os.Getenv("KOMANDO_SFTEST_SECRET"), nil, readOnly, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, u
}

func liveSFRun(t *testing.T, db *sql.DB, write bool, sql string, args ...any) *Result {
	t.Helper()
	plan, err := driver.ClassifySQL("snowflake", sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	res, err := Run(context.Background(), db, "snowflake", plan, Options{Write: write, Limit: 100, Timeout: 2 * time.Minute, Args: args})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return res
}

func TestSnowflakeLive(t *testing.T) {
	ro, _ := liveSF(t, true)
	rw, _ := liveSF(t, false)
	ctx := context.Background()
	res := liveSFRun(t, ro, false, "select current_version() as v, ? as x", "a'b")
	if row := res.Results[0].Rows[0]; row[1] != "a'b" || row[0] == "" {
		t.Errorf("select: %v", row)
	}
	liveSFRun(t, rw, true, "create or replace table komando_sf_t (id number(38,0), total number(10,2), placed timestamp_ntz, v variant, b binary)")
	t.Cleanup(func() { rw.ExecContext(context.Background(), "drop table if exists komando_sf_t") })
	ins := liveSFRun(t, rw, true, "insert into komando_sf_t select 1, 1.50, '2024-01-01 10:00:00.5', parse_json('{\"a\": [1, 2]}'), to_binary('48656C6C6F', 'HEX')")
	if n := ins.Results[0].RowsAffected; n == nil || *n != 1 {
		t.Errorf("insert: %+v", ins.Results[0])
	}
	if _, err := ro.ExecContext(ctx, "insert into komando_sf_t (id) values (2)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert on a read-only conn: %v", err)
	}
	row := liveSFRun(t, ro, false, "select * from komando_sf_t").Results[0].Rows[0]
	if row[0] != int64(1) || row[1] != "1.50" || row[2] != "2024-01-01 10:00:00.5" {
		t.Errorf("values: %#v", row)
	}
	if v, ok := row[3].(map[string]any); !ok || len(v["a"].([]any)) != 2 {
		t.Errorf("variant: %#v", row[3])
	}
	tables, err := Schema(ctx, ro, "snowflake", []string{"komando_sf_t"}, time.Minute)
	if err != nil || len(tables) != 1 || len(tables[0].Columns) != 5 || !strings.HasPrefix(tables[0].Columns[1].Type, "NUMBER(10,2)") {
		t.Errorf("schema: %+v, %v", tables, err)
	}
	if info, err := Info(ctx, ro, "snowflake", time.Minute); err != nil || info["version"] == nil {
		t.Errorf("info: %v, %v", info, err)
	}
	if _, err := Activity(ctx, ro, "snowflake", false, time.Minute); err != nil {
		t.Errorf("activity: %v", err)
	}
	if _, err := Sizes(ctx, ro, "snowflake", 5, time.Minute); err != nil {
		t.Errorf("sizes: %v", err)
	}
	liveSFRun(t, ro, false, "EXPLAIN select * from komando_sf_t")
	// a statement that runs a while is cancelled on the server when the run times out
	plan, _ := driver.ClassifySQL("snowflake", "select system$wait(30)")
	start := time.Now()
	if _, err := Run(ctx, ro, "snowflake", plan, Options{Limit: 1, Timeout: 3 * time.Second}); errCode(err) != "TIMEOUT" || time.Since(start) > 15*time.Second {
		t.Errorf("timeout: %v after %s", err, time.Since(start))
	}
}
