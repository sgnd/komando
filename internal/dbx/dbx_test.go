package dbx

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func openLite(t *testing.T, path string, readOnly bool) *Conn {
	t.Helper()
	tg, err := driver.Parse("sqlite://" + path)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), "sqlite://"+path, tg, "", nil, readOnly, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Conn{sqlDB: db}
}

// Conn wraps the handle so tests read like the CLI.
type Conn struct{ sqlDB *sql.DB }

func run(t *testing.T, c *Conn, sql string, o Options) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("sqlite", sql)
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), c.sqlDB, "sqlite", plan, o)
}

func TestRunSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	rw := openLite(t, path, false)
	if _, err := run(t, rw, "create table t(id integer primary key, name text); insert into t(name) values ('a'), ('b'), ('c')", Options{Write: true}); err != nil {
		t.Fatal(err)
	}

	// dry run rolls back
	res, err := run(t, rw, "update t set name = 'z' where id = 1", Options{Write: true, DryRun: true})
	if err != nil || !res.RolledBack || res.Committed || *res.Results[0].RowsAffected != 1 {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	res, _ = run(t, rw, "select name from t where id = 1", Options{})
	if res.Results[0].Rows[0][0] != "a" {
		t.Errorf("dry run changed data: %v", res.Results[0].Rows)
	}

	// limit and truncation
	res, _ = run(t, rw, "select * from t order by id", Options{Limit: 2})
	if r := res.Results[0]; r.RowCount != 2 || !r.Truncated {
		t.Errorf("limit: %+v", r)
	}

	// args
	plan, _ := driver.ClassifySQL("sqlite", "select id from t where name = ?")
	res, err = Run(context.Background(), rw.sqlDB, "sqlite", plan, Options{Args: []any{"c"}})
	if err != nil || res.Results[0].Rows[0][0] != int64(3) {
		t.Errorf("args: %+v %v", res, err)
	}
}

// The database must refuse writes on a read-only run even when the
// classifier is wrong: this is the first safety layer.
func TestReadOnlyIsEnforcedByTheDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	rw := openLite(t, path, false)
	if _, err := run(t, rw, "create table t(id integer)", Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	ro := openLite(t, path, true)
	lie := driver.SQLPlan{Statements: []driver.Statement{{SQL: "insert into t values (1)", Keyword: "INSERT", Risk: driver.RiskRead}}}
	_, err := Run(context.Background(), ro.sqlDB, "sqlite", lie, Options{})
	if e, ok := err.(*out.Error); !ok || e.Code != "WRITE_REQUIRES_FLAG" {
		t.Fatalf("read-only connection accepted a write: %v", err)
	}
}

func TestNoTxStatement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	rw := openLite(t, path, false)
	res, err := run(t, rw, "vacuum", Options{Write: true, DryRun: true})
	if err != nil || res.Results[0].Skipped == "" || res.Committed {
		t.Errorf("dry-run vacuum should be skipped: %+v %v", res, err)
	}
	if _, err := run(t, rw, "select 1; vacuum", Options{Write: true}); err == nil {
		t.Error("vacuum mixed with other statements accepted")
	}
	if res, err := run(t, rw, "vacuum", Options{Write: true}); err != nil || !res.Committed {
		t.Errorf("vacuum: %+v %v", res, err)
	}
}

func TestJSONValue(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{"x", `"x"`},
		{[]byte("text"), `"text"`},
		{[]byte{0, 255}, `{"base64":"AP8="}`},
		{ts, `"2026-01-02T03:04:05Z"`},
		{int64(1) << 60, `"1152921504606846976"`},
		{int64(42), "42"},
	}
	for _, c := range cases {
		b, _ := json.Marshal(JSONValue(c.in))
		if string(b) != c.want {
			t.Errorf("%v: got %s want %s", c.in, b, c.want)
		}
	}
}

func TestStatementResultJSON(t *testing.T) {
	b, _ := StatementResult{SQL: "select 1 where 2 > 1", Columns: []Column{{Name: "x"}}, Rows: [][]any{}}.MarshalJSON()
	if s := string(b); !strings.Contains(s, `"rows":[]`) || !strings.Contains(s, `"row_count":0`) || !strings.Contains(s, "2 > 1") {
		t.Errorf("row statement JSON: %s", s)
	}
	b, _ = json.Marshal(StatementResult{SQL: "create table x(i int)"})
	if s := string(b); strings.Contains(s, "rows") {
		t.Errorf("DDL JSON should have no rows: %s", s)
	}
}
