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

// These run when KOMANDO_BQTEST names a BigQuery project and dataset to
// test against (bigquery://PROJECT/DATASET?location=EU, a dataset the
// login may create tables in), with KOMANDO_BQTEST_KEY holding a service
// account key (JSON); without it, gcloud's login is used. They make and
// drop the table komando_bq_t, and read a few bytes. They have not yet
// run against a real project.

func liveBQ(t *testing.T, readOnly bool) *sql.DB {
	t.Helper()
	u := os.Getenv("KOMANDO_BQTEST")
	if u == "" {
		t.Skip("set KOMANDO_BQTEST (and KOMANDO_BQTEST_KEY) to run")
	}
	tg, err := driver.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), u, tg, os.Getenv("KOMANDO_BQTEST_KEY"), nil, readOnly, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func liveBQRun(t *testing.T, db *sql.DB, o Options, sql string, args ...any) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("bigquery", sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	o.Limit, o.Timeout, o.Args = 100, 2*time.Minute, args
	return Run(context.Background(), db, "bigquery", plan, o)
}

func TestBigQueryLive(t *testing.T) {
	ro := liveBQ(t, true)
	rw := liveBQ(t, false)
	ctx := context.Background()
	res, err := liveBQRun(t, ro, Options{}, "select ? as x, 1 as n, timestamp '2024-01-01 00:00:00.5 UTC' as ts, [1, 2] as a, struct(1 as p) as s", "a'b")
	if err != nil {
		t.Fatal(err)
	}
	if row := res.Results[0].Rows[0]; row[0] != "a'b" || row[1] != int64(1) || row[2] != "2024-01-01T00:00:00.5Z" {
		t.Errorf("select: %v", row)
	}
	if _, err := liveBQRun(t, rw, Options{Write: true}, "create or replace table komando_bq_t (id int64 not null, total numeric, placed timestamp)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { liveBQRun(t, rw, Options{Write: true}, "drop table if exists komando_bq_t") })
	res, err = liveBQRun(t, rw, Options{Write: true}, "insert into komando_bq_t values (1, numeric '12.50', current_timestamp()), (2, null, null)")
	if err != nil || *res.Results[0].RowsAffected != 2 {
		t.Fatalf("insert: %+v %v", res, err)
	}
	// BigQuery's own dry run refuses the write on a read-only connection
	if _, err := ro.ExecContext(ctx, "insert into komando_bq_t values (3, null, null)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("read-only insert: %v", err)
	}
	// a dry run runs nothing and says what it would read
	res, err = liveBQRun(t, rw, Options{Write: true, DryRun: true}, "delete from komando_bq_t where id = 1")
	if err != nil || res.Results[0].BytesProcessed == nil || !strings.Contains(res.Results[0].Skipped, "DELETE") {
		t.Errorf("dry run: %+v %v", res, err)
	}
	res, err = liveBQRun(t, ro, Options{}, "select count(*) as n, max(total) as t from komando_bq_t")
	if err != nil || res.Results[0].Rows[0][0] != int64(2) || res.Results[0].Rows[0][1] != "12.5" {
		t.Errorf("count: %+v %v", res, err)
	}
	if _, err := liveBQRun(t, ro, Options{MaxBilled: 1}, "select * from komando_bq_t"); errCode(err) != "DB_BYTES_LIMIT" && err != nil {
		t.Errorf("cap: %v", err)
	}
	tables, err := Schema(ctx, ro, "bigquery", []string{"komando_bq_t"}, time.Minute)
	if err != nil || len(tables[0].Columns) != 3 || tables[0].Columns[0].Nullable {
		t.Errorf("schema: %+v %v", tables, err)
	}
	if _, err := Info(ctx, ro, "bigquery", time.Minute); err != nil {
		t.Errorf("info: %v", err)
	}
	if _, err := Activity(ctx, ro, "bigquery", false, time.Minute); err != nil {
		t.Errorf("activity: %v", err)
	}
	if _, err := Sizes(ctx, ro, "bigquery", 5, time.Minute); err != nil {
		t.Errorf("sizes: %v", err)
	}
}
