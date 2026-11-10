package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/store"
)

// A BigQuery conn is HTTPS to Google with the certificate checked, so conn
// add keeps the URL as written and doctor has nothing to say about it; an
// http:// endpoint across the network is flagged; what BigQuery cannot do
// here says so before connecting.
func TestBigQueryConns(t *testing.T) {
	invHome(t)
	raw := "bigquery://my-project/shop?location=EU"
	d := mustRun(t, "conn", "add", "bq", raw)
	mustRun(t, "conn", "add", "bq-emu", "bigquery://my-project/shop?endpoint=http://127.0.0.1:9050")
	mustRun(t, "conn", "add", "bq-plain", "bigquery://my-project/shop?endpoint=http://bq.internal:9050")
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Conns["bq"].URL != raw || strings.Contains(fmt.Sprint(d["warnings"]), "TLS") {
		t.Errorf("saved %s, warnings %v", st.Conns["bq"].URL, d["warnings"])
	}
	if got := plainConn(st.Conns["bq"]) + plainConn(st.Conns["bq-emu"]); got != "" {
		t.Errorf("plainConn: %q", got)
	}
	if got := plainConn(st.Conns["bq-plain"]); !strings.Contains(got, "plain HTTP") {
		t.Errorf("plainConn of an http endpoint: %q", got)
	}
	wantCode(t, "USAGE", "conn", "add", "bq-tls", "bigquery://my-project?tls=false")
	wantCode(t, "USAGE", "conn", "add", "bq-user", "bigquery://me@my-project")
	wantCode(t, "NOT_SUPPORTED", "db", "dump", "bq", "--to", t.TempDir()+"/s.sql")
	wantCode(t, "NOT_SUPPORTED", "db", "restore", "bq", "--from", "x.sql", "--dry-run")
	wantCode(t, "NOT_SUPPORTED", "db", "explain", "bq", "select 1", "--analyze")
	wantCode(t, "NOT_SUPPORTED", "db", "user", "add", "bq", "bob", "--password-ref", "secret:x")
	wantCode(t, "NOT_SUPPORTED", "db", "user", "rm", "bq", "bob")
	wantCode(t, "NOT_SUPPORTED", "db", "grant", "bq", "bob", "--role", "readers")
	// the classifier says what needs --write before anything connects
	wantCode(t, "WRITE_REQUIRES_FLAG", "db", "query", "bq", "insert into shop.t values (1)")
	wantCode(t, "SQL_HIDDEN_CODE", "db", "query", "bq", "select 1 # a\x0bdrop table t")
	wantCode(t, "USAGE", "db", "query", "bq", "declare x int64")
	wantCode(t, "USAGE", "db", "query", "bq", "select 1", "--max-bytes", "lots")
	p := mustRun(t, "policy", "check", "--for", "bigquery", "export data options (uri = 'gs://b/*.csv') as select 1")
	if p["risk"] != "destructive" {
		t.Errorf("policy check: %v", p)
	}
	// --max-bytes is BigQuery's
	mustRun(t, "conn", "add", "lite", "sqlite://"+t.TempDir()+"/x.db")
	wantCode(t, "USAGE", "db", "query", "lite", "select 1", "--max-bytes", "1GB")
}

func TestBigQueryText(t *testing.T) {
	if w := weakTLS("", "bigquery://my-project?endpoint=http://bq.internal:9050"); len(w) != 1 || !strings.Contains(w[0], "http://") {
		t.Errorf("weakTLS: %v", w)
	}
	if w := weakTLS("", "bigquery://my-project"); len(w) != 0 {
		t.Errorf("weakTLS of Google's endpoint: %v", w)
	}
	n := int64(3 << 30)
	d := queryData{Result: &dbx.Result{Results: []dbx.StatementResult{{SQL: "select 1", Columns: []dbx.Column{{Name: "n"}}, Rows: [][]any{{1}}, RowCount: 1, BytesProcessed: &n}}}}
	if s := d.Text(); !strings.Contains(s, "(BigQuery read 3.0 GiB)") {
		t.Errorf("text: %s", s)
	}
	info := dbInfoData{"conn": "bq", "kind": "bigquery", "project": "my-project", "dataset": "shop", "location": "EU"}
	if s := info.Text(); !strings.Contains(s, "project:") || !strings.Contains(s, "location:") {
		t.Errorf("info: %s", s)
	}
}

func TestMaxBytesFlag(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "0": -1, "50GB": 50 << 30, "1048576": 1 << 20} {
		if got, err := maxBytesFlag("bigquery", in); err != nil || got != want {
			t.Errorf("%q: %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := maxBytesFlag("postgres", "1GB"); err == nil {
		t.Error("postgres took --max-bytes")
	}
}
