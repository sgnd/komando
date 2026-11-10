package dbx

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// fakeSF answers like Snowflake's SQL API, enough for the client: logins
// by key pair or token, asynchronous statements, partitions, errors.
type fakeSF struct {
	t         *testing.T
	pub       *rsa.PublicKey // key-pair logins check against it
	token     string         // the programmatic access token it takes
	sub       string         // ACCOUNT.USER the token must be for
	mu        sync.Mutex
	bodies    []map[string]any
	hdrs      []http.Header
	cancel    []string
	polls     int
	throttled bool
	results   map[string]result
}

type result struct {
	status int
	body   string
	slow   bool // stays running until cancelled
}

func (f *fakeSF) login(r *http.Request) bool {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch r.Header.Get("X-Snowflake-Authorization-Token-Type") {
	case "PROGRAMMATIC_ACCESS_TOKEN":
		return f.token != "" && tok == f.token
	case "KEYPAIR_JWT":
		parts := strings.Split(tok, ".")
		if len(parts) != 3 || f.pub == nil {
			return false
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) != nil {
			return false
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var c struct {
			Iss, Sub string
			Iat, Exp int64
		}
		json.Unmarshal(raw, &c)
		der, _ := x509.MarshalPKIXPublicKey(f.pub)
		fp := sha256.Sum256(der)
		return c.Sub == f.sub && c.Iss == f.sub+".SHA256:"+base64.StdEncoding.EncodeToString(fp[:]) && c.Exp-c.Iat <= 3600
	}
	return false
}

func (f *fakeSF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !f.login(r) {
		w.WriteHeader(401)
		io.WriteString(w, `{"code":"390144","message":"JWT token is invalid."}`)
		return
	}
	f.hdrs = append(f.hdrs, r.Header.Clone())
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/statements")
	switch {
	case r.Method == "POST" && path == "":
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		stmt := fmt.Sprint(body["statement"])
		if strings.Contains(stmt, "throttled") && !f.throttled {
			f.throttled = true
			w.WriteHeader(429)
			return
		}
		if r.URL.Query().Get("async") != "true" || r.URL.Query().Get("requestId") == "" {
			f.t.Errorf("request without async or requestId: %s", r.URL)
		}
		h := fmt.Sprintf("01b0-%d", len(f.bodies))
		f.results[h] = f.answer(stmt)
		w.WriteHeader(202)
		fmt.Fprintf(w, `{"code":"333334","message":"Asynchronous execution in progress.","statementHandle":%q,"statementStatusUrl":"/api/v2/statements/%s?requestId=x"}`, h, h)
	case r.Method == "POST" && strings.HasSuffix(path, "/cancel"):
		f.cancel = append(f.cancel, strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/cancel"))
		io.WriteString(w, `{"code":"000604","message":"cancelled"}`)
	case r.Method == "GET":
		f.polls++
		res, ok := f.results[strings.TrimPrefix(path, "/")]
		switch {
		case !ok:
			w.WriteHeader(404)
		case r.URL.Query().Get("partition") == "1":
			io.WriteString(w, `{"data":[["3"],["4"]]}`)
		case res.slow:
			w.WriteHeader(202)
			fmt.Fprintf(w, `{"code":"333334","statementHandle":%q}`, strings.TrimPrefix(path, "/"))
		default:
			w.WriteHeader(res.status)
			io.WriteString(w, res.body)
		}
	default:
		w.WriteHeader(405)
	}
}

func rowsJSON(cols string, rows ...string) result {
	return result{200, `{"resultSetMetaData":{"numRows":1,"format":"jsonv2","rowType":[` + cols + `]},"data":[` + strings.Join(rows, ",") + `],"code":"090001"}`, false}
}

func col(name, typ string) string {
	return fmt.Sprintf(`{"name":%q,"type":%q,"precision":38,"scale":0,"nullable":true}`, name, typ)
}

func fail(code, msg string) result {
	return result{422, fmt.Sprintf(`{"code":%q,"message":%q,"sqlState":"42000","statementHandle":"x"}`, code, msg), false}
}

func (f *fakeSF) answer(stmt string) result {
	if r, ok := f.results["sql:"+strings.TrimSpace(stmt)]; ok {
		return r
	}
	switch {
	case strings.HasPrefix(stmt, "insert"):
		return result{200, `{"resultSetMetaData":{"numRows":1,"rowType":[` + col("number of rows inserted", "fixed") + `]},"data":[["3"]],"stats":{"numRowsInserted":3}}`, false}
	case strings.HasPrefix(stmt, "select values"):
		return rowsJSON(col("big", "fixed")+","+`{"name":"dec","type":"fixed","precision":10,"scale":2}`+","+col("f", "real")+","+col("b", "boolean")+","+
			col("d", "date")+","+col("tm", "time")+","+col("ntz", "timestamp_ntz")+","+col("ltz", "timestamp_ltz")+","+col("tz", "timestamp_tz")+","+
			col("bin", "binary")+","+col("v", "variant")+","+col("n", "text")+","+col("s", "text"),
			`["123456789012345678901234567890","1.50","2.5","true","19723","3723.500000000","1704067200.123000000","1704067200.000000000","1704067200.000000000 1500","48656c6c6f",`+
				`"{\"a\":[1,2.5,12345678901234567890],\"b\":null}",null,"x"]`)
	case strings.Contains(stmt, "CURRENT_VERSION()"):
		return rowsJSON(col("version", "text")+","+col("account", "text"), `["9.1.0","XY12345"]`)
	case strings.HasPrefix(stmt, "select parts"):
		return result{200, `{"resultSetMetaData":{"numRows":4,"rowType":[` + col("n", "fixed") + `],"partitionInfo":[{"rowCount":2},{"rowCount":2}]},"data":[["1"],["2"]]}`, false}
	case strings.HasPrefix(stmt, "select slow"):
		return result{slow: true}
	case strings.HasPrefix(stmt, "select bad"):
		return fail("001003", "SQL compilation error:\nsyntax error line 1 at position 7 unexpected 'bad'.")
	case strings.HasPrefix(stmt, "select nowh"):
		return fail("000606", "No active warehouse selected in the current session.  Select an active warehouse with the 'use warehouse' command.")
	case strings.HasPrefix(stmt, "select priv"):
		return fail("003001", "SQL access control error:\nInsufficient privileges to operate on table 'T'")
	case strings.HasPrefix(stmt, "select missing"):
		return fail("002003", "SQL compilation error:\nObject 'MISSING' does not exist or not authorized.")
	case strings.HasPrefix(stmt, "select twice"):
		return fail("000008", "Actual statement count 2 did not match the desired statement count 1.")
	}
	return rowsJSON(col("1", "fixed"), `["1"]`)
}

func (f *fakeSF) last() (map[string]any, http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[len(f.bodies)-1], f.hdrs[len(f.hdrs)-1]
}

// sfServer is a TLS server whose certificate, from a private CA, names
// *.snowflakecomputing.com; dial sends every connection to it, as --via
// does, so komando dials by the account's name.
func sfServer(t *testing.T, f *fakeSF) (caPEM string, dial DialFunc, asked *[]string) {
	t.Helper()
	f.t = t
	if f.results == nil {
		f.results = map[string]result{}
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "snowflake"}, DNSNames: []string{"*.snowflakecomputing.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	srv := httptest.NewUnstartedServer(f)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshakes are on purpose
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	var mu sync.Mutex
	asked = &[]string{}
	dial = func(ctx context.Context, network, a string) (net.Conn, error) {
		mu.Lock()
		*asked = append(*asked, a)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	old := driver.ResolveSecret
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	driver.ResolveSecret = func(string) (string, error) { return caPEM, nil }
	t.Cleanup(func() { driver.ResolveSecret = old })
	return caPEM, dial, asked
}

const sfTestURL = "snowflake://app@myorg-acct/ANALYTICS/PUBLIC?warehouse=WH&role=RO&ca=secret:sfca"

func openSF(t *testing.T, raw, secret string, readOnly bool, dial DialFunc) (*sql.DB, error) {
	t.Helper()
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), raw, tg, secret, dial, readOnly, "komando/test")
	if err == nil {
		t.Cleanup(func() { db.Close() })
	}
	return db, err
}

func sfRun(t *testing.T, d *sql.DB, o Options, sql string) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("snowflake", sql)
	if err != nil {
		t.Fatal(err)
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	o.Limit = 100
	return Run(context.Background(), d, "snowflake", plan, o)
}

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// Key-pair login: komando signs the token Snowflake checks, sends the
// conn's database, schema, warehouse and role with each statement, one
// statement per request, and dials the account by name over TLS checked
// against the conn's CA.
func TestSnowflakeKeyPair(t *testing.T) {
	key, keyPEM := testKey(t)
	f := &fakeSF{pub: &key.PublicKey, sub: "MYORG-ACCT.APP"}
	_, dial, asked := sfServer(t, f)
	db, err := openSF(t, sfTestURL, keyPEM, true, dial)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := driver.ClassifySQL("snowflake", "select ? as x, ? as y")
	if _, err := Run(context.Background(), db, "snowflake", plan, Options{Limit: 10, Timeout: 30 * time.Second, Args: []any{"a'b", int64(7)}}); err != nil {
		t.Fatal(err)
	}
	body, h := f.last()
	params, _ := body["parameters"].(map[string]any)
	if body["database"] != "ANALYTICS" || body["schema"] != "PUBLIC" || body["warehouse"] != "WH" || body["role"] != "RO" ||
		params["MULTI_STATEMENT_COUNT"] != "1" || params["QUERY_TAG"] != "komando/test" || body["timeout"] == nil {
		t.Errorf("body: %v", body)
	}
	b, _ := json.Marshal(body["bindings"])
	if string(b) != `{"1":{"type":"TEXT","value":"a'b"},"2":{"type":"FIXED","value":"7"}}` {
		t.Errorf("bindings: %s", b)
	}
	if h.Get("User-Agent") != "komando/test" || h.Get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT" {
		t.Errorf("headers: %v", h)
	}
	if len(*asked) == 0 || (*asked)[0] != "myorg-acct.snowflakecomputing.com:443" {
		t.Errorf("dialed %v", *asked)
	}
	// another key is refused, and the hint names the fingerprint to check
	_, other := testKey(t)
	if _, err := openSF(t, sfTestURL, other, true, dial); errCode(err) != "DB_AUTH" || !strings.Contains(err.(*out.Error).Hint, "RSA_PUBLIC_KEY_FP") {
		t.Errorf("wrong key: %v", err)
	}
	// without the conn's CA the certificate does not check out
	if _, err := openSF(t, strings.Replace(sfTestURL, "&ca=secret:sfca", "", 1), keyPEM, true, dial); errCode(err) != "DB_CONNECT" ||
		!strings.Contains(err.(*out.Error).Hint, "ca=secret:NAME") {
		t.Errorf("unknown CA: %v", err)
	}
}

func TestSnowflakeToken(t *testing.T) {
	f := &fakeSF{token: "pat-good"}
	_, dial, _ := sfServer(t, f)
	db, err := openSF(t, sfTestURL, "pat-good\n", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sfRun(t, db, Options{}, "select 1"); err != nil {
		t.Fatal(err)
	}
	if _, h := f.last(); h.Get("Authorization") != "Bearer pat-good" || h.Get("X-Snowflake-Authorization-Token-Type") != "PROGRAMMATIC_ACCESS_TOKEN" {
		t.Errorf("headers: %v", h)
	}
	if _, err := openSF(t, sfTestURL, "a-password", true, dial); errCode(err) != "DB_AUTH" || !strings.Contains(err.(*out.Error).Hint, "takes no passwords") {
		t.Errorf("a password: %v", err)
	}
	for secret, code := range map[string]string{
		"": "DB_AUTH",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n": "USAGE",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n":                     "USAGE",
		"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n":                     "USAGE",
		"-----BEGIN nothing": "USAGE",
	} {
		if _, err := openSF(t, sfTestURL, secret, true, dial); errCode(err) != code {
			t.Errorf("secret %.30q: %v, want %s", secret, err, code)
		}
	}
}

// Without --write a statement that is not a read never reaches Snowflake,
// even when sent past the classifier; with --write it goes alone, and a
// dry run only reports it.
func TestSnowflakeReadOnly(t *testing.T) {
	f := &fakeSF{token: "pat-good"}
	_, dial, _ := sfServer(t, f)
	ro, err := openSF(t, sfTestURL, "pat-good", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	n := len(f.bodies)
	if _, err := ro.ExecContext(context.Background(), "insert into t values (1)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert on a read-only connection: %v", err)
	}
	if _, err := ro.ExecContext(context.Background(), "select 1; select 2"); errCode(err) != "USAGE" {
		t.Errorf("two statements: %v", err)
	}
	if _, err := sfRun(t, ro, Options{}, "insert into t values (1)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert without --write: %v", err)
	}
	if len(f.bodies) != n {
		t.Errorf("a write reached the server: %v", f.bodies[n:])
	}
	rw, err := openSF(t, sfTestURL, "pat-good", false, dial)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sfRun(t, rw, Options{Write: true, DryRun: true}, "insert into t values (1)")
	if err != nil || res.Results[0].Skipped == "" || len(f.bodies) != n+1 {
		t.Errorf("dry run: %+v, %v", res, err)
	}
	res, err = sfRun(t, rw, Options{Write: true}, "insert into t values (1), (2), (3)")
	if err != nil || res.Results[0].RowsAffected == nil || *res.Results[0].RowsAffected != 3 || !res.Committed {
		t.Errorf("insert: %+v, %v", res, err)
	}
	if _, err := sfRun(t, rw, Options{Write: true}, "insert into t values (1); select 1"); errCode(err) != "USAGE" {
		t.Errorf("a write with others: %v", err)
	}
}

func TestSnowflakeValues(t *testing.T) {
	f := &fakeSF{token: "pat-good"}
	_, dial, _ := sfServer(t, f)
	db, err := openSF(t, sfTestURL, "pat-good", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sfRun(t, db, Options{}, "select values")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(res.Results[0].Rows[0])
	want := `["123456789012345678901234567890","1.50",2.5,true,"2024-01-01","01:02:03.5","2024-01-01 00:00:00.123","2024-01-01T00:00:00Z","2024-01-01T01:00:00+01:00",` +
		`{"base64":"SGVsbG8="},{"a":[1,2.5,"12345678901234567890"],"b":null},null,"x"]`
	if string(got) != want {
		t.Errorf("values:\n got %s\nwant %s", got, want)
	}
	types := []string{}
	for _, c := range res.Results[0].Columns {
		types = append(types, c.Type)
	}
	if strings.Join(types, " ") != "number(38,0) number(10,2) float boolean date time timestamp_ntz timestamp_ltz timestamp_tz binary variant varchar varchar" {
		t.Errorf("types: %v", types)
	}
	// a result in two partitions, and a statement that runs a while
	res, err = sfRun(t, db, Options{}, "select parts")
	if err != nil || fmt.Sprint(res.Results[0].Rows) != "[[1] [2] [3] [4]]" {
		t.Errorf("partitions: %+v, %v", res, err)
	}
	if _, err := sfRun(t, db, Options{}, "select throttled"); err != nil {
		t.Errorf("429 is retried: %v", err)
	}
}

// A run that times out cancels the statement on the server.
func TestSnowflakeCancel(t *testing.T) {
	f := &fakeSF{token: "pat-good"}
	_, dial, _ := sfServer(t, f)
	db, err := openSF(t, sfTestURL, "pat-good", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sfRun(t, db, Options{Timeout: 300 * time.Millisecond}, "select slow")
	if errCode(err) != "TIMEOUT" {
		t.Errorf("slow: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cancel) != 1 || f.polls == 0 {
		t.Errorf("cancelled %v after %d polls", f.cancel, f.polls)
	}
}

func TestSnowflakeErrors(t *testing.T) {
	f := &fakeSF{token: "pat-good"}
	_, dial, _ := sfServer(t, f)
	db, err := openSF(t, sfTestURL, "pat-good", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	for sql, code := range map[string]string{
		"select bad": "DB_ERROR", "select nowh": "DB_ERROR", "select priv": "DB_PRIVILEGE", "select missing": "DB_ERROR", "select twice": "USAGE",
	} {
		_, err := sfRun(t, db, Options{}, sql)
		if errCode(err) != code || strings.Contains(err.Error(), "\n") {
			t.Errorf("%s: %v, want %s", sql, err, code)
		}
	}
	if _, err := sfRun(t, db, Options{}, "select nowh"); !strings.Contains(err.(*out.Error).Hint, "?warehouse=") {
		t.Errorf("no warehouse: %v", err)
	}
	f.results["sql:SELECT 1"] = fail("002043", "SQL compilation error:\nDatabase 'NOPE' does not exist or not authorized.")
	if _, err := openSF(t, sfTestURL, "pat-good", true, dial); errCode(err) != "DB_NOT_FOUND" {
		t.Errorf("missing database: %v", err)
	}
}

// db info, activity, kill, users, grants and schema read Snowflake's own
// views; activity's pid is komando's, and kill finds the query by it.
func TestSnowflakeOps(t *testing.T) {
	f := &fakeSF{token: "pat-good", results: map[string]result{}}
	_, dial, _ := sfServer(t, f)
	qid := "01b2c3d4-0000-1111-0000-000000000001"
	f.results["sql:"+strings.TrimSpace(sfRunning)] = rowsJSON(col("query_id", "text")+","+col("session_id", "fixed")+","+col("state", "text"), `["`+qid+`","4242","RUNNING"]`)
	f.results["sql:SHOW USERS"] = rowsJSON(col("name", "text")+","+col("login_name", "text")+","+col("disabled", "text")+","+col("type", "text")+","+col("password_hash", "text"),
		`["APP","APP","false","SERVICE","x"]`)
	f.results["sql:SHOW ROLES"] = rowsJSON(col("name", "text"), `["ANALYST_RO"]`)
	f.results["sql:SHOW GRANTS TO USER app"] = rowsJSON(col("role", "text"), `["ANALYST_RO"]`)
	f.results[`sql:SHOW GRANTS TO ROLE "ANALYST_RO"`] = rowsJSON(col("privilege", "text")+","+col("granted_on", "text")+","+col("name", "text")+","+col("grant_option", "text"),
		`["USAGE","DATABASE","ANALYTICS","false"]`, `["SELECT","TABLE","ANALYTICS.PUBLIC.ORDERS","false"]`, `["REFERENCES","TABLE","ANALYTICS.PUBLIC.ORDERS","true"]`)
	f.results["sql:SHOW GRANTS TO USER ghost"] = fail("002003", "User 'GHOST' does not exist or not authorized.")
	f.results["sql:SHOW GRANTS TO ROLE ghost"] = fail("002003", "Role 'GHOST' does not exist or not authorized.")
	db, err := openSF(t, sfTestURL, "pat-good", false, dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rows, err := Activity(ctx, db, "snowflake", false, time.Minute)
	if err != nil || len(rows) != 1 || rows[0]["pid"] != sfPID(qid) || rows[0]["session_id"] != int64(4242) {
		t.Fatalf("activity: %v, %v", rows, err)
	}
	if err := Kill(ctx, db, "snowflake", sfPID(qid), false); err != nil {
		t.Fatal(err)
	}
	if body, _ := f.last(); body["statement"] != "SELECT SYSTEM$CANCEL_QUERY(?)" || fmt.Sprint(body["bindings"]) != "map[1:map[type:TEXT value:"+qid+"]]" {
		t.Errorf("kill: %v", body)
	}
	if err := Kill(ctx, db, "snowflake", sfPID(qid), true); err != nil {
		t.Fatal(err)
	}
	if body, _ := f.last(); body["statement"] != "SELECT SYSTEM$ABORT_SESSION(?)" || !strings.Contains(fmt.Sprint(body["bindings"]), "FIXED value:4242") {
		t.Errorf("kill --session: %v", body)
	}
	if err := Kill(ctx, db, "snowflake", 7, false); errCode(err) != "SESSION_NOT_FOUND" {
		t.Errorf("unknown pid: %v", err)
	}
	if _, err := Locks(ctx, db, "snowflake", time.Minute); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("locks: %v", err)
	}
	users, err := Users(ctx, db, "snowflake", time.Minute)
	if err != nil || len(users) != 2 || users[0]["user_type"] != "SERVICE" || users[0]["password_hash"] != nil || users[1]["type"] != "role" {
		t.Errorf("users: %v, %v", users, err)
	}
	grants, err := Grants(ctx, db, "snowflake", "app", "", time.Minute)
	if err != nil || len(grants) != 3 || grants[2]["privileges"] != "SELECT,REFERENCES (with grant option)" || grants[0]["object"] != "ANALYST_RO" {
		t.Errorf("grants: %v, %v", grants, err)
	}
	if _, err := Grants(ctx, db, "snowflake", "ghost", "", time.Minute); errCode(err) != "DB_USER_NOT_FOUND" {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := Grants(ctx, db, "snowflake", "a b", "", time.Minute); errCode(err) != "USAGE" {
		t.Errorf("bad name: %v", err)
	}
	if _, err := UserChange(ctx, db, "snowflake", "add", UserSpec{Name: "bob", Password: "x"}, true); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("user add: %v", err)
	}
	if _, err := GrantSQL(ctx, db, "snowflake", Grant{User: "bob", Privs: []string{"SELECT"}, On: "x"}); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("grant: %v", err)
	}
	info, err := Info(ctx, db, "snowflake", time.Minute)
	if err != nil || info["version"] == nil {
		t.Errorf("info: %v, %v", info, err)
	}
	if _, err := Sizes(ctx, db, "snowflake", 5, time.Minute); err != nil {
		t.Errorf("sizes: %v", err)
	}
}

func TestSnowflakeSchema(t *testing.T) {
	f := &fakeSF{token: "pat-good", results: map[string]result{}}
	_, dial, _ := sfServer(t, f)
	db, err := openSF(t, sfTestURL, "pat-good", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	tables := rowsJSON(col("TABLE_SCHEMA", "text")+","+col("TABLE_NAME", "text")+","+col("T", "text")+","+col("ROW_COUNT", "fixed")+","+col("CLUSTERING_KEY", "text"),
		`["PUBLIC","ORDERS","table","42","LINEAR(placed)"]`, `["PUBLIC","V","view",null,null]`)
	columns := rowsJSON(col("COLUMN_NAME", "text")+","+col("T", "text")+","+col("IS_NULLABLE", "text")+","+col("COLUMN_DEFAULT", "text")+","+col("IS_IDENTITY", "text"),
		`["ID","NUMBER(38,0)","NO",null,"YES"]`, `["ITEM","VARCHAR(100)","YES","'x'","NO"]`)
	f.mu.Lock()
	f.results["sql:"+strings.TrimSpace(sfSchemaList)] = tables
	f.results["sql:"+strings.TrimSpace(sfColumnsSQL)] = columns
	f.results[`sql:SHOW PRIMARY KEYS IN TABLE "PUBLIC"."ORDERS"`] = rowsJSON(col("column_name", "text"), `["ID"]`)
	f.mu.Unlock()
	list, err := Schema(context.Background(), db, "snowflake", nil, time.Minute)
	if err != nil || len(list) != 2 || list[1].Type != "view" || *list[0].RowEstimate != 42 {
		t.Fatalf("schema: %+v, %v", list, err)
	}
	one, err := Schema(context.Background(), db, "snowflake", []string{"public.orders"}, time.Minute)
	if err != nil || len(one) != 1 || len(one[0].Columns) != 2 || !one[0].Columns[0].PrimaryKey || one[0].Columns[0].Identity == "" ||
		*one[0].Columns[1].Default != "'x'" || one[0].Indexes[0].Definition != "CLUSTER BY (placed)" {
		t.Errorf("schema orders: %+v, %v", one, err)
	}
	if _, err := Schema(context.Background(), db, "snowflake", []string{"nope"}, time.Minute); errCode(err) != "TABLE_NOT_FOUND" {
		t.Errorf("unknown table: %v", err)
	}
}

func TestSnowflakeEpoch(t *testing.T) {
	for in, want := range map[string]string{
		"0.000000000":         "1970-01-01T00:00:00Z",
		"-1.500000000":        "1969-12-31T23:59:58.5Z",
		"1616173619":          "2021-03-19T17:06:59Z",
		"1616173619000000000": "2021-03-19T17:06:59Z",
	} {
		got, ok := sfEpoch(in)
		if !ok || got.UTC().Format(time.RFC3339Nano) != want {
			t.Errorf("%s: %v %v, want %s", in, got.UTC(), ok, want)
		}
	}
	for _, bad := range []string{"x", "1.1234567890", "1.2a"} {
		if _, ok := sfEpoch(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
	if sfBinding(nil)["value"] != nil || sfBinding(2.5)["type"] != "REAL" || sfBinding(true)["value"] != "true" || sfBinding([]byte("A"))["value"] != "41" ||
		sfBinding(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC))["type"] != "TIMESTAMP_TZ" {
		t.Error("bindings")
	}
}
