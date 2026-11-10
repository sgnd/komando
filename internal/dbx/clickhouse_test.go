package dbx

import (
	"context"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// fakeCH answers like ClickHouse's HTTP interface, enough for the client:
// the settings probe, rows, a summary for writes and errors.
type fakeCH struct {
	mu       sync.Mutex
	readonly string // the user's profile
	dialect  string
	reqs     []*http.Request
	bodies   []string
}

func (f *fakeCH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	body := string(b)
	f.mu.Lock()
	f.reqs, f.bodies = append(f.reqs, r), append(f.bodies, body)
	f.mu.Unlock()
	fail := func(code int, status int, text string) {
		w.Header().Set("X-ClickHouse-Exception-Code", fmt.Sprint(code))
		w.WriteHeader(status)
		fmt.Fprintf(w, "Code: %d. DB::Exception: %s. (X) (version 24.8.1.1 (official build))\n", code, text)
	}
	rows := func(lines ...string) {
		w.Header().Set("X-ClickHouse-Format", chFormat)
		io.WriteString(w, strings.Join(lines, "\n")+"\n")
	}
	switch {
	case r.Header.Get("X-ClickHouse-Key") == "wrong":
		fail(516, 403, "u: Authentication failed: password is incorrect, or there is no user with such name.\n\nIf you have installed ClickHouse")
	case r.Header.Get("X-ClickHouse-Database") == "nodb":
		fail(81, 404, "Database nodb does not exist")
	case strings.Contains(body, "system.settings"):
		dialect := f.dialect
		if dialect == "" {
			dialect = "clickhouse"
		}
		rows(`["name","value"]`, `["String","String"]`, `["dialect","`+dialect+`"]`, `["readonly","`+f.readonly+`"]`)
	case strings.HasPrefix(body, "insert"):
		if r.URL.Query().Get("readonly") == "1" || f.readonly != "0" {
			fail(164, 500, "u: Cannot execute query in readonly mode")
			return
		}
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"3","written_rows":"3"}`)
	case strings.HasPrefix(body, "select values"):
		rows(`["big","small","i64","dec","arr","m","n","f","b","s"]`,
			`["UInt64","Nullable(Int64)","Int64","Decimal(10, 2)","Array(Int32)","Map(String, UInt8)","Nullable(String)","Float64","Bool","LowCardinality(String)"]`,
			`["18446744073709551615","-5","9007199254740993",1.50,[1,2],{"k":1},null,2.5,true,"x"]`)
	case strings.HasPrefix(body, "select fail-mid"):
		rows(`["n"]`, `["UInt64"]`, `["1"]`, `Code: 395. DB::Exception: boom: while executing. (FUNCTION_THROW_IF_VALUE_IS_NON_ZERO) (version 24.8.1.1 (official build))`)
	case strings.HasPrefix(body, "select fail-row"):
		rows(`["n","m"]`, `["UInt64","UInt8"]`, `["1",0]`, `["Code: 395. DB::Exception: boom. (X) (version 24.8.1.1 (official build))"]`)
	case strings.HasPrefix(body, "select other-format"):
		w.Header().Set("X-ClickHouse-Format", "JSON")
		io.WriteString(w, "{}")
	case strings.HasPrefix(body, "select bad"):
		fail(62, 400, "Syntax error: failed at position 8")
	default:
		rows(`["1"]`, `["UInt8"]`, `[1]`)
	}
}

func (f *fakeCH) last() (url.Values, http.Header, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reqs[len(f.reqs)-1]
	return r.URL.Query(), r.Header, f.bodies[len(f.bodies)-1]
}

func openFake(t *testing.T, srv *httptest.Server, query, password string, readOnly bool, dial DialFunc) (*sql.DB, error) {
	t.Helper()
	host := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
	raw := "clickhouse://u@" + host + "/" + query
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), raw, tg, password, dial, readOnly, "komando/test")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { db.Close() })
	return db, nil
}

func chRun(t *testing.T, d *sql.DB, write bool, sql string, args ...any) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("clickhouse", sql)
	if err != nil {
		t.Fatal(err)
	}
	return Run(context.Background(), d, "clickhouse", plan, Options{Write: write, Limit: 100, Timeout: 30 * time.Second, Args: args})
}

// Without --write every request asks the server for readonly=1; with it,
// a write goes without, and its rows written come back.
func TestClickHouseReadOnlyRequests(t *testing.T) {
	f := &fakeCH{readonly: "0"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	ro, err := openFake(t, srv, "analytics", "pw", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chRun(t, ro, false, "select {p1:String} as x", "a'b"); err != nil {
		t.Fatal(err)
	}
	q, h, body := f.last()
	if q.Get("readonly") != "1" || q.Get("max_execution_time") == "" || q.Get("param_p1") != "a'b" || q.Get("http_write_exception_in_output_format") != "0" {
		t.Errorf("read request: %v", q)
	}
	if h.Get("X-ClickHouse-User") != "u" || h.Get("X-ClickHouse-Key") != "pw" || h.Get("X-ClickHouse-Database") != "analytics" || h.Get("User-Agent") != "komando/test" {
		t.Errorf("headers: %v", h)
	}
	if !strings.HasSuffix(body, "\nFORMAT "+chFormat) || strings.Contains(fmt.Sprint(q), "pw") {
		t.Errorf("body %q, query %v", body, q)
	}
	// a write without --write never reaches the server; on a read-only
	// connection the server is asked for readonly=1 even if it did
	if _, err := chRun(t, ro, false, "insert into t values (1)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert without --write: %v", err)
	}
	if _, err := ro.ExecContext(context.Background(), "insert into t values (1)"); errCode(clickhouseErr(err)) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert on a read-only connection: %v", err)
	}
	rw, err := openFake(t, srv, "analytics", "pw", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := chRun(t, rw, true, "insert into t values (1)")
	if err != nil {
		t.Fatal(err)
	}
	q, _, _ = f.last()
	if q.Has("readonly") || res.Results[0].RowsAffected == nil || *res.Results[0].RowsAffected != 3 || !res.Committed {
		t.Errorf("write: %v %+v", q, res.Results[0])
	}
	// reads keep readonly=1 with --write too
	if _, err := chRun(t, rw, true, "select 1"); err != nil {
		t.Fatal(err)
	}
	if q, _, _ := f.last(); q.Get("readonly") != "1" {
		t.Errorf("a read with --write: %v", q)
	}
	// a dry run reports a write and sends nothing
	n := len(f.reqs)
	plan, _ := driver.ClassifySQL("clickhouse", "insert into t values (1)")
	res, err = Run(context.Background(), rw, "clickhouse", plan, Options{Write: true, DryRun: true})
	if err != nil || res.Results[0].Skipped == "" || len(f.reqs) != n {
		t.Errorf("dry run: %+v %v (%d requests)", res, err, len(f.reqs)-n)
	}
}

// A user whose profile is read-only refuses any setting in the request
// (readonly=1) or a change of readonly (2): komando sends what it may.
func TestClickHouseProfileReadOnly(t *testing.T) {
	for _, c := range []struct {
		profile          string
		readonly, others bool
	}{{"1", false, false}, {"2", false, true}} {
		f := &fakeCH{readonly: c.profile}
		srv := httptest.NewServer(f)
		d, err := openFake(t, srv, "", "", true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := chRun(t, d, false, "select 1"); err != nil {
			t.Fatal(err)
		}
		q, h, _ := f.last()
		if q.Has("readonly") != c.readonly || q.Has("max_execution_time") != c.others || h.Get("X-ClickHouse-Key") != "" {
			t.Errorf("profile readonly=%s: %v", c.profile, q)
		}
		w, err := openFake(t, srv, "", "", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := chRun(t, w, true, "insert into t values (1)"); errCode(err) != "DB_PRIVILEGE" || !strings.Contains(err.Error(), "may only read") {
			t.Errorf("profile readonly=%s, write: %v", c.profile, err)
		}
		srv.Close()
	}
}

func TestClickHouseValues(t *testing.T) {
	srv := httptest.NewServer(&fakeCH{readonly: "0"})
	defer srv.Close()
	d, err := openFake(t, srv, "", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := chRun(t, d, false, "select values")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Results[0]
	got := fmt.Sprintf("%#v", r.Rows[0])
	want := `[]interface {}{"18446744073709551615", -5, "9007199254740993", "1.50", []interface {}{1, 2}, map[string]interface {}{"k":1}, interface {}(nil), 2.5, true, "x"}`
	if got != want {
		t.Errorf("values:\n got %s\nwant %s", got, want)
	}
	if r.Columns[3].Type != "Decimal(10, 2)" || r.Columns[9].Type != "LowCardinality(String)" {
		t.Errorf("types keep their case: %+v", r.Columns)
	}
}

func TestClickHouseErrors(t *testing.T) {
	f := &fakeCH{readonly: "0"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	if _, err := openFake(t, srv, "", "wrong", true, nil); errCode(err) != "DB_AUTH" || strings.Contains(err.Error(), "installed ClickHouse") {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := openFake(t, srv, "nodb", "", true, nil); errCode(err) != "DB_NOT_FOUND" {
		t.Errorf("missing database: %v", err)
	}
	d, err := openFake(t, srv, "", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	for sql, code := range map[string]string{
		"select fail-mid": "DB_ERROR", "select fail-row": "DB_ERROR", "select bad": "DB_ERROR", "select other-format": "USAGE",
	} {
		_, err := chRun(t, d, false, sql)
		if errCode(err) != code {
			t.Errorf("%s: %v, want %s", sql, err, code)
		}
		if code == "DB_ERROR" && (strings.Contains(err.Error(), "version 24") || strings.Contains(err.Error(), "Code:") || !strings.Contains(err.Error(), "boom") && sql != "select bad") {
			t.Errorf("%s: the message keeps ClickHouse's wrapping: %v", sql, err)
		}
	}
	// a read-only profile gets no settings, so a late failure is a row
	f1 := &fakeCH{readonly: "1"}
	srv1 := httptest.NewServer(f1)
	defer srv1.Close()
	d1, err := openFake(t, srv1, "", "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chRun(t, d1, false, "select fail-row"); errCode(err) != "DB_ERROR" || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failure as a row: %v", err)
	}
	f2 := &fakeCH{readonly: "0", dialect: "kusto"}
	srv2 := httptest.NewServer(f2)
	defer srv2.Close()
	if _, err := openFake(t, srv2, "", "", true, nil); errCode(err) != "SQL_STRING_RULES" {
		t.Errorf("kusto dialect: %v", err)
	}
}

// HTTPS checks the certificate: against the conn's ?ca=, or not at all
// with tls=skip-verify; the hints name what to do when it fails.
func TestClickHouseTLS(t *testing.T) {
	srv := httptest.NewTLSServer(&fakeCH{readonly: "0"})
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	old := driver.ResolveSecret
	driver.ResolveSecret = func(string) (string, error) { return caPEM, nil }
	defer func() { driver.ResolveSecret = old }()
	open := func(opts string) error {
		raw := "clickhouse://u@" + host + "/?" + opts
		tg, err := driver.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		db, err := Open(context.Background(), raw, tg, "", nil, true, "komando/test")
		if err == nil {
			db.Close()
		}
		return err
	}
	if err := open("tls=true&ca=secret:chca"); err != nil {
		t.Errorf("with the CA: %v", err)
	}
	if err := open("tls=skip-verify"); err != nil {
		t.Errorf("skip-verify: %v", err)
	}
	if err := open("tls=true"); errCode(err) != "DB_CONNECT" || !strings.Contains(fmt.Sprint(err.(*out.Error).Hint), "ca=secret:NAME") {
		t.Errorf("unknown CA: %v", err)
	}
	plain := httptest.NewServer(&fakeCH{readonly: "0"})
	defer plain.Close()
	raw := "clickhouse://u@" + strings.TrimPrefix(plain.URL, "http://") + "/?tls=true"
	tg, _ := driver.Parse(raw)
	if _, err := Open(context.Background(), raw, tg, "", nil, true, "komando/test"); errCode(err) != "DB_CONNECT" || !strings.Contains(err.(*out.Error).Hint, "no TLS") {
		t.Errorf("HTTPS to a plain server: %v", err)
	}
}

// --via hands the dialer the host name: the SSH server resolves it.
func TestClickHouseVia(t *testing.T) {
	srv := httptest.NewServer(&fakeCH{readonly: "0"})
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var asked []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(srv.URL, "http://"))
	}
	raw := "clickhouse://u@ch.invalid:" + port + "/"
	tg, _ := driver.Parse(raw)
	db, err := Open(context.Background(), raw, tg, "", dial, true, "komando/test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(asked) == 0 || asked[0] != "ch.invalid:"+port {
		t.Errorf("dialed %v", asked)
	}
}
