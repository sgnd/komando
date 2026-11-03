package dbx

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func TestTimeText(t *testing.T) {
	ts := time.Date(2024, 2, 29, 10, 11, 12, 500000000, time.UTC)
	day := time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC)
	plus2 := time.FixedZone("", 2*3600)
	cases := []struct {
		kind, typ string
		v         time.Time
		want      string
	}{
		{"postgres", "DATE", day, "2024-02-29"},
		{"postgres", "TIMESTAMP", ts, "2024-02-29 10:11:12.5"},
		{"postgres", "TIMESTAMP", day, "2024-02-29 00:00:00"},
		{"postgres", "TIMESTAMPTZ", ts.In(plus2), "2024-02-29T10:11:12.5Z"},
		{"sqlite", "DATE", day, "2024-02-29"},
		{"sqlite", "DATE", ts, "2024-02-29 10:11:12.5"},
		{"sqlite", "DATETIME", ts.In(plus2), "2024-02-29 12:11:12.5+02:00"},
		{"postgres", "", ts, "2024-02-29T10:11:12.5Z"},
	}
	for _, c := range cases {
		if got := timeText(c.kind, c.typ, c.v); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.kind, c.typ, got, c.want)
		}
	}
}

func TestColValue(t *testing.T) {
	empty := map[string]string{"base64": ""}
	if v := colValue("postgres", "BYTEA", []byte{}); v.(map[string]string)["base64"] != "" {
		t.Errorf("empty bytea: %v", v)
	}
	if v := colValue("postgres", "BYTEA", []byte("ab")); v.(map[string]string)["base64"] != "YWI=" {
		t.Errorf("bytea: %v", v)
	}
	if v, ok := colValue("mysql", "BLOB", []byte{}).(map[string]string); !ok || v["base64"] != empty["base64"] {
		t.Errorf("empty blob: %v", v)
	}
	// MySQL dates come as the server's text: zero dates stay as they are
	if v := colValue("mysql", "DATETIME", []byte("0000-00-00 00:00:00")); v != "0000-00-00 00:00:00" {
		t.Errorf("zero datetime: %v", v)
	}
	if v := colValue("mysql", "DATE", []byte("2024-02-29")); v != "2024-02-29" {
		t.Errorf("date: %v", v)
	}
	if v := colValue("mysql", "UNSIGNED BIGINT", []byte("18446744073709551615")); v != "18446744073709551615" {
		t.Errorf("unsigned bigint: %#v", v)
	}
	if v := colValue("mysql", "INT", []byte("7")); v != int64(7) {
		t.Errorf("int: %#v", v)
	}
}

// One JSON type per column: when one value is too big for a JSON number,
// every value of that column is a string.
func TestSameTypeColumns(t *testing.T) {
	raw := [][]any{{uint64(1), int64(5)}, {uint64(18446744073709551615), int64(6)}}
	rows := [][]any{{driver.JSONValue(raw[0][0]), driver.JSONValue(raw[0][1])}, {driver.JSONValue(raw[1][0]), driver.JSONValue(raw[1][1])}}
	sameTypeColumns(rows, raw)
	if rows[0][0] != "1" || rows[1][0] != "18446744073709551615" {
		t.Errorf("big column: %#v", rows)
	}
	if rows[0][1] != int64(5) {
		t.Errorf("small column changed: %#v", rows)
	}
}

func TestArgCountAndTimeout(t *testing.T) {
	e, ok := checkArgs("postgres", "select $1, $2", 1).(*out.Error)
	if !ok || e.Exit != out.ExitUsage {
		t.Errorf("arg count: %v", e)
	}
	if err := checkArgs("postgres", "select $1", 1); err != nil {
		t.Error(err)
	}
	te := timeoutErr(out.Errf(out.ExitTimeout, "TIMEOUT", "", "query timed out"), 30*time.Second).(*out.Error)
	if te.Message != "query timed out after 30s" || te.Hint != "narrow the query (WHERE, LIMIT), or allow more time with --timeout 1m" {
		t.Errorf("timeout: %q / %q", te.Message, te.Hint)
	}
	for d, want := range map[time.Duration]string{30 * time.Second: "30s", 2 * time.Minute: "2m", 90 * time.Second: "1m30s", time.Hour: "1h"} {
		if got := shortDuration(d); got != want {
			t.Errorf("%v: %q", d, got)
		}
	}
}

func TestSQLiteDatesArgsAndTruncation(t *testing.T) {
	rw := openLite(t, filepath.Join(t.TempDir(), "d.db"), false)
	if _, err := run(t, rw, "create table d(day date, at datetime, b blob, s text); insert into d values ('2024-02-29', '2024-02-29 10:11:12', x'', 'aaaaaaaaaa'), ('2024-03-01', '2024-03-01 00:00:00', x'00', 'bbbbbbbbbb')", Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	res, err := run(t, rw, "select day, at, b from d order by day", Options{})
	if err != nil {
		t.Fatal(err)
	}
	row := res.Results[0].Rows[0]
	if row[0] != "2024-02-29" || row[1] != "2024-02-29 10:11:12" {
		t.Errorf("dates: %#v", row)
	}
	if b, ok := row[2].(map[string]string); !ok || b["base64"] != "" {
		t.Errorf("empty blob: %#v", row[2])
	}
	res, _ = run(t, rw, "select s from d", Options{MaxBytes: 5})
	if r := res.Results[0]; r.Truncated != "bytes" || r.RowCount != 1 {
		t.Errorf("byte cap: %+v", r)
	}
	plan, _ := driver.ClassifySQL("sqlite", "select ? , ?")
	_, err = Run(context.Background(), rw.sqlDB, "sqlite", plan, Options{Args: []any{"x"}})
	if e, ok := err.(*out.Error); !ok || e.Exit != out.ExitUsage {
		t.Errorf("arg mismatch: %v", err)
	}
}
