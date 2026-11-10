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
	"errors"
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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// fakeBQ answers like BigQuery's REST API and Google's token endpoint,
// enough for the client: service account logins, dry runs, jobs, pages
// of results, cancels, datasets and tables.
type fakeBQ struct {
	t       *testing.T
	pub     *rsa.PublicKey // service account logins check against it; nil: no login needed
	noType  bool           // dry runs leave out the statement type (an emulator)
	mu      sync.Mutex
	dry     []map[string]any // dry-run job configurations
	jobs    []map[string]any // jobs that ran
	cancels []string
	paths   []string
	auth    []string        // the Authorization header of each API request
	slow    map[string]bool // job IDs that keep running
	queries map[string]string
	// tokenHang, when set, keeps the token endpoint from answering until closed
	tokenHang chan struct{}
}

func (f *fakeBQ) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/token" {
		if f.tokenHang != nil {
			<-f.tokenHang
		}
		f.token(w, r)
		return
	}
	if f.pub != nil && r.Header.Get("Authorization") != "Bearer tok-1" {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"code":401,"message":"Request is missing required authentication credential.","errors":[{"reason":"required"}]}}`)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/")
	f.paths = append(f.paths, r.Method+" "+path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	switch {
	case r.Method == "POST" && strings.HasSuffix(path, "/jobs"):
		var job map[string]any
		json.NewDecoder(r.Body).Decode(&job)
		f.insert(w, job)
	case r.Method == "POST" && strings.HasSuffix(path, "/cancel"):
		id := strings.TrimSuffix(path[strings.LastIndex(strings.TrimSuffix(path, "/cancel"), "/")+1:], "/cancel")
		f.cancels = append(f.cancels, id+"@"+r.URL.Query().Get("location"))
		delete(f.slow, id)
		io.WriteString(w, `{"kind":"bigquery#jobCancelResponse"}`)
	case r.Method == "GET" && strings.Contains(path, "/queries/"):
		f.results(w, r, path[strings.LastIndex(path, "/")+1:])
	case r.Method == "GET":
		f.meta(w, path, r.URL.Query().Get("pageToken"))
	default:
		w.WriteHeader(405)
	}
}

// token checks the service account's signed assertion and gives tok-1.
func (f *fakeBQ) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	parts := strings.Split(r.Form.Get("assertion"), ".")
	ok := len(parts) == 3 && f.pub != nil
	if ok {
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		ok = rsa.VerifyPKCS1v15(f.pub, crypto.SHA256, sum[:], sig) == nil
	}
	if !ok {
		w.WriteHeader(400)
		io.WriteString(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
		return
	}
	io.WriteString(w, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`)
}

func bqErrJSON(status int, reason, msg string) string {
	return fmt.Sprintf(`{"error":{"code":%d,"message":%q,"errors":[{"reason":%q,"message":%q}]}}`, status, msg, reason, msg)
}

func (f *fakeBQ) insert(w http.ResponseWriter, job map[string]any) {
	conf, _ := job["configuration"].(map[string]any)
	q, _ := conf["query"].(map[string]any)
	sqlText := fmt.Sprint(q["query"])
	low := strings.ToLower(sqlText)
	if strings.Contains(low, "select bad") {
		w.WriteHeader(400)
		io.WriteString(w, bqErrJSON(400, "invalidQuery", "Syntax error: Unexpected identifier \"bad\" at [1:8]"))
		return
	}
	if ds, _ := q["defaultDataset"].(map[string]any); strings.Contains(low, "missing") || ds["datasetId"] == "missing" {
		w.WriteHeader(404)
		io.WriteString(w, bqErrJSON(404, "notFound", "Not found: Table p:shop.missing was not found in location EU"))
		return
	}
	if strings.Contains(low, "denied") {
		w.WriteHeader(403)
		io.WriteString(w, bqErrJSON(403, "accessDenied", "Access Denied: Project p: User does not have bigquery.jobs.create permission"))
		return
	}
	if conf["dryRun"] == true {
		f.dry = append(f.dry, conf)
		st := map[string]string{"select": "SELECT", "with": "SELECT", "from": "SELECT", "insert": "INSERT", "delete": "DELETE",
			"create": "CREATE_TABLE", "drop": "DROP_TABLE", "call": "SCRIPT", "execute": "SCRIPT"}[strings.Fields(low)[0]]
		if strings.Contains(low, "script") {
			st = "SCRIPT"
		}
		if strings.Contains(low, "sneaky") {
			st = "INSERT" // what BigQuery saw, not what komando did
		}
		if f.noType {
			st = ""
		}
		bytes := "1234"
		if strings.Contains(low, "huge") {
			bytes = fmt.Sprint(int64(50) << 30)
		}
		fmt.Fprintf(w, `{"jobReference":{"projectId":"my-project","location":"EU"},"statistics":{"totalBytesProcessed":%q,"query":{"statementType":%q,
			"totalBytesProcessed":%q,"totalBytesProcessedAccuracy":"PRECISE","referencedTables":[{"projectId":"my-project","datasetId":"shop","tableId":"orders"}],
			"schema":{"fields":[{"name":"n","type":"INTEGER","mode":"NULLABLE"}]}}},"status":{"state":"DONE"}}`, bytes, st, bytes)
		return
	}
	ref, _ := job["jobReference"].(map[string]any)
	id := fmt.Sprint(ref["jobId"])
	f.jobs = append(f.jobs, job)
	f.queries[id] = sqlText
	if strings.Contains(low, "slow") {
		f.slow[id] = true
	}
	fmt.Fprintf(w, `{"jobReference":{"projectId":"my-project","jobId":%q,"location":"EU"},"status":{"state":"RUNNING"}}`, id)
}

func (f *fakeBQ) results(w http.ResponseWriter, r *http.Request, id string) {
	q, ok := f.queries[id]
	low := strings.ToLower(q)
	switch {
	case !ok:
		w.WriteHeader(404)
		io.WriteString(w, bqErrJSON(404, "notFound", "Not found: Job my-project:EU."+id))
	case f.slow[id]:
		io.WriteString(w, `{"jobComplete":false}`)
	case strings.Contains(low, "slow"): // cancelled
		w.WriteHeader(400)
		io.WriteString(w, bqErrJSON(400, "stopped", "Job execution was cancelled: User requested cancellation"))
	case strings.HasPrefix(low, "insert"), strings.HasPrefix(low, "delete"):
		io.WriteString(w, `{"jobComplete":true,"numDmlAffectedRows":"3","totalBytesProcessed":"99"}`)
	case strings.HasPrefix(low, "create"), strings.HasPrefix(low, "drop"):
		io.WriteString(w, `{"jobComplete":true,"totalBytesProcessed":"0"}`)
	case strings.Contains(low, "values"):
		io.WriteString(w, `{"jobComplete":true,"totalBytesProcessed":"1234","totalRows":"1","schema":{"fields":[
			{"name":"i","type":"INTEGER"},{"name":"f","type":"FLOAT"},{"name":"b","type":"BOOLEAN"},{"name":"ts","type":"TIMESTAMP"},
			{"name":"by","type":"BYTES"},{"name":"num","type":"NUMERIC"},{"name":"j","type":"JSON"},{"name":"d","type":"DATE"},
			{"name":"tags","type":"STRING","mode":"REPEATED"},{"name":"rec","type":"RECORD","fields":[{"name":"a","type":"INTEGER"},{"name":"b","type":"STRING"}]},
			{"name":"nul","type":"STRING"},{"name":"inf","type":"FLOAT"}]},
			"rows":[{"f":[{"v":"9007199254740993"},{"v":"2.5"},{"v":"true"},{"v":"1704067200123456"},{"v":"SGk="},{"v":"123456789012345678.123456789"},
			{"v":"{\"a\":[1,2.5,12345678901234567890]}"},{"v":"2024-01-01"},{"v":[{"v":"x"},{"v":"y"}]},{"v":{"f":[{"v":"7"},{"v":"z"}]}},{"v":null},{"v":"Infinity"}]}]}`)
	case strings.Contains(low, "pages") && r.URL.Query().Get("pageToken") == "":
		io.WriteString(w, `{"jobComplete":true,"totalRows":"3","pageToken":"p2","schema":{"fields":[{"name":"n","type":"INTEGER"}]},"rows":[{"f":[{"v":"1"}]},{"f":[{"v":"2"}]}]}`)
	case strings.Contains(low, "pages"):
		io.WriteString(w, `{"jobComplete":true,"rows":[{"f":[{"v":"3"}]}]}`)
	case strings.Contains(low, "information_schema.jobs"):
		io.WriteString(w, `{"jobComplete":true,"schema":{"fields":[{"name":"job_id","type":"STRING"},{"name":"project_id","type":"STRING"},{"name":"state","type":"STRING"}]},
			"rows":[{"f":[{"v":"bquxjob_1"},{"v":"other-project"},{"v":"RUNNING"}]}]}`)
	case strings.Contains(low, "table_storage"):
		io.WriteString(w, `{"jobComplete":true,"schema":{"fields":[{"name":"name","type":"STRING"},{"name":"bytes","type":"INTEGER"}]},"rows":[{"f":[{"v":"shop"},{"v":"4096"}]}]}`)
	case strings.Contains(low, "session_user"):
		io.WriteString(w, `{"jobComplete":true,"schema":{"fields":[{"name":"user","type":"STRING"}]},"rows":[{"f":[{"v":"sa@my-project.iam.gserviceaccount.com"}]}]}`)
	default:
		io.WriteString(w, `{"jobComplete":true,"totalBytesProcessed":"1234","schema":{"fields":[{"name":"n","type":"INTEGER"}]},"rows":[{"f":[{"v":"1"}]}]}`)
	}
}

func (f *fakeBQ) meta(w http.ResponseWriter, path, page string) {
	switch strings.TrimPrefix(path, "my-project/") + page {
	case "datasets/shop/tablest2":
		io.WriteString(w, `{"tables":[{"tableReference":{"tableId":"returns"},"type":"TABLE"}]}`)
	case "datasets":
		io.WriteString(w, `{"datasets":[{"datasetReference":{"datasetId":"shop"}},{"datasetReference":{"datasetId":"logs"}}]}`)
	case "datasets/shop":
		io.WriteString(w, `{"location":"EU"}`)
	case "datasets/shop/tables":
		io.WriteString(w, `{"tables":[{"tableReference":{"tableId":"orders"},"type":"TABLE"},{"tableReference":{"tableId":"big_orders"},"type":"VIEW"}],"nextPageToken":"t2"}`)
	case "datasets/logs/tables":
		io.WriteString(w, `{"tables":[{"tableReference":{"tableId":"events"},"type":"TABLE"}]}`)
	case "datasets/shop/tables/orders":
		io.WriteString(w, `{"type":"TABLE","numRows":"42","schema":{"fields":[{"name":"id","type":"INTEGER","mode":"REQUIRED"},
			{"name":"item","type":"STRING"},{"name":"addr","type":"RECORD","fields":[{"name":"city","type":"STRING"}]},{"name":"tags","type":"STRING","mode":"REPEATED"}]},
			"timePartitioning":{"type":"DAY","field":"placed"},"clustering":{"fields":["item"]},"tableConstraints":{"primaryKey":{"columns":["id"]}}}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, bqErrJSON(404, "notFound", "Not found: "+path))
	}
}

// bqServer is a TLS server whose certificate, from a private CA, names
// Google's API and token hosts; dial sends every connection to it, as
// --via does, so komando dials by name.
func bqServer(t *testing.T, f *fakeBQ) (dial DialFunc, asked *[]string) {
	t.Helper()
	f.t = t
	f.slow, f.queries = map[string]bool{}, map[string]string{}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "google"}, DNSNames: []string{"bigquery.googleapis.com", "oauth2.googleapis.com", "emu.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey)
	srv := httptest.NewUnstartedServer(f)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
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
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	driver.ResolveSecret = func(string) (string, error) { return caPEM, nil }
	oldCreds := bqDefaultCredentials // gcloud's login, here a token of its own
	bqDefaultCredentials = func(context.Context) (*google.Credentials, error) {
		return &google.Credentials{TokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "tok-1"})}, nil
	}
	t.Cleanup(func() { driver.ResolveSecret, bqDefaultCredentials = old, oldCreds })
	return dial, asked
}

// saKey is a service account key file whose token URI is the fake's.
func saKey(t *testing.T) (*rsa.PrivateKey, string) {
	key, keyPEM := testKey(t)
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "my-project", "private_key_id": "k1",
		"private_key": keyPEM, "client_email": "sa@my-project.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token"})
	return key, string(b)
}

const bqTestURL = "bigquery://my-project/shop?location=EU&ca=secret:bqca"

func openBQ(t *testing.T, raw, secret string, readOnly bool, dial DialFunc) (*sql.DB, error) {
	t.Helper()
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(context.Background(), raw, tg, secret, dial, readOnly, "komando/Test Bot")
	if err == nil {
		t.Cleanup(func() { db.Close() })
	}
	return db, err
}

func bqRunSQL(t *testing.T, d *sql.DB, o Options, sql string) (*Result, error) {
	t.Helper()
	plan, err := driver.ClassifySQL("bigquery", sql)
	if err != nil {
		t.Fatal(err)
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	o.Limit = 100
	return Run(context.Background(), d, "bigquery", plan, o)
}

// A token endpoint that does not answer is bounded by the request's
// context, and one that cannot be reached is a network problem, not a
// login to renew.
func TestBigQueryTokenNetwork(t *testing.T) {
	key, sa := saKey(t)
	f := &fakeBQ{pub: &key.PublicKey, tokenHang: make(chan struct{})}
	dial, _ := bqServer(t, f)
	t.Cleanup(func() { close(f.tokenHang) }) // runs before the server closes
	tg, _ := driver.Parse(bqTestURL)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_, err := Open(ctx, bqTestURL, tg, sa, dial, true, "komando")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || errCode(err) == "DB_AUTH" {
			t.Errorf("a token endpoint that does not answer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("the token fetch ignored the context's deadline")
	}
	refused := func(ctx context.Context, network, a string) (net.Conn, error) {
		if strings.HasPrefix(a, "oauth2.") {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
		}
		return dial(ctx, network, a)
	}
	_, err := Open(context.Background(), bqTestURL, tg, sa, refused, true, "komando")
	if errCode(err) != "DB_CONNECT" || !strings.Contains(err.(*out.Error).Hint, "--via") {
		t.Errorf("a token endpoint that cannot be reached: %v", err)
	}
}

// A service account key logs in through the token endpoint, dialed the
// conn's way and checked against its CA; every statement is dry-run
// first, then runs as a job with komando's own ID, the URL's dataset and
// location, the byte cap and a label.
func TestBigQueryLogin(t *testing.T) {
	key, sa := saKey(t)
	f := &fakeBQ{pub: &key.PublicKey}
	dial, asked := bqServer(t, f)
	db, err := openBQ(t, bqTestURL, sa, true, dial)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := driver.ClassifySQL("bigquery", "select ? as x")
	res, err := Run(context.Background(), db, "bigquery", plan, Options{Limit: 10, Timeout: 30 * time.Second, Args: []any{"a'b"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Results[0]; r.BytesProcessed == nil || *r.BytesProcessed != 1234 || r.Rows[0][0] != int64(1) {
		t.Errorf("result: %+v", r)
	}
	job := f.jobs[len(f.jobs)-1]
	conf := job["configuration"].(map[string]any)
	q := conf["query"].(map[string]any)
	ref := job["jobReference"].(map[string]any)
	b, _ := json.Marshal(q["queryParameters"])
	if !strings.HasPrefix(fmt.Sprint(ref["jobId"]), "komando_") || ref["location"] != "EU" || q["useLegacySql"] != false ||
		q["maximumBytesBilled"] != fmt.Sprint(BQDefaultMaxBytes) || q["parameterMode"] != "POSITIONAL" ||
		string(b) != `[{"parameterType":{"type":"STRING"},"parameterValue":{"value":"a'b"}}]` || conf["jobTimeoutMs"] == nil {
		t.Errorf("job: %v", job)
	}
	if ds, _ := json.Marshal(q["defaultDataset"]); string(ds) != `{"datasetId":"shop","projectId":"my-project"}` {
		t.Errorf("default dataset: %s", ds)
	}
	if l, _ := json.Marshal(conf["labels"]); string(l) != `{"komando":"test_bot"}` {
		t.Errorf("labels: %s", l)
	}
	for _, a := range *asked {
		if a != "bigquery.googleapis.com:443" && a != "oauth2.googleapis.com:443" {
			t.Errorf("dialed %s", a)
		}
	}
	// another key is refused by the token endpoint
	_, other := saKey(t)
	if _, err := openBQ(t, bqTestURL, other, true, dial); errCode(err) != "DB_AUTH" {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := openBQ(t, bqTestURL, `{"type":"authorized_user"}`, true, dial); errCode(err) != "DB_AUTH" {
		t.Errorf("not a service account: %v", err)
	}
	// without the conn's CA the certificate does not check out
	if _, err := openBQ(t, strings.Replace(bqTestURL, "&ca=secret:bqca", "", 1), sa, true, dial); errCode(err) != "DB_CONNECT" ||
		!strings.Contains(err.(*out.Error).Hint, "ca=secret:NAME") {
		t.Errorf("unknown CA: %v", err)
	}
	// no key and no gcloud login: say how to log in
	old := bqDefaultCredentials
	bqDefaultCredentials = func(context.Context) (*google.Credentials, error) {
		return nil, fmt.Errorf("could not find default credentials")
	}
	t.Cleanup(func() { bqDefaultCredentials = old })
	if _, err := openBQ(t, bqTestURL, "", true, dial); errCode(err) != "DB_AUTH" || !strings.Contains(err.(*out.Error).Hint, "application-default login") {
		t.Errorf("no login: %v", err)
	}
	// the dataset in the URL does not exist
	if _, err := openBQ(t, "bigquery://my-project/missing?ca=secret:bqca", sa, true, dial); errCode(err) != "DB_NOT_FOUND" {
		t.Errorf("missing dataset: %v", err)
	}
}

// Without --write only what BigQuery itself calls a SELECT runs, after
// the classifier's own check; a script is refused; the byte cap stops a
// query before it runs.
func TestBigQueryReadOnly(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	ro, err := openBQ(t, "bigquery://my-project/shop?endpoint=https://bigquery.googleapis.com&ca=secret:bqca", "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// the driver checks again: a write that reaches it without the CLI
	if _, err := ro.ExecContext(ctx, "insert into t values (1)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("insert: %v", err)
	}
	// komando saw a read, BigQuery a write: refused before it runs
	n := len(f.jobs)
	if _, err := bqRunSQL(t, ro, Options{}, "select sneaky"); errCode(err) != "WRITE_REQUIRES_FLAG" || len(f.jobs) != n {
		t.Errorf("sneaky: %v", err)
	}
	if _, err := bqRunSQL(t, ro, Options{}, "select 1 as script"); errCode(err) != "WRITE_REQUIRES_FLAG" || len(f.jobs) != n {
		t.Errorf("script: %v", err)
	}
	if _, err := bqRunSQL(t, ro, Options{}, "select huge"); errCode(err) != "DB_BYTES_LIMIT" || len(f.jobs) != n {
		t.Errorf("huge: %v", err)
	}
	if res, err := bqRunSQL(t, ro, Options{MaxBilled: 100 << 30}, "select huge"); err != nil || *res.Results[0].BytesProcessed != 1234 {
		t.Errorf("huge with a higher cap: %v", err)
	}
	if q := f.jobs[len(f.jobs)-1]["configuration"].(map[string]any)["query"].(map[string]any); q["maximumBytesBilled"] != fmt.Sprint(int64(100)<<30) {
		t.Errorf("cap: %v", q)
	}
	if _, err := bqRunSQL(t, ro, Options{MaxBilled: -1}, "select huge"); err != nil {
		t.Errorf("huge without a cap: %v", err)
	}
	if q := f.jobs[len(f.jobs)-1]["configuration"].(map[string]any)["query"].(map[string]any); q["maximumBytesBilled"] != nil {
		t.Errorf("no cap: %v", q)
	}
	// Google's endpoint always says the statement type
	f.noType = true
	if _, err := bqRunSQL(t, ro, Options{}, "select 1"); err == nil || !strings.Contains(err.Error(), "did not say") {
		t.Errorf("no statement type: %v", err)
	}
	// an emulator may not: the classifier's rating is all there is; and
	// gcloud's login never goes to a host that is not Google's
	emu, err := openBQ(t, "bigquery://my-project/shop?endpoint=https://emu.test&ca=secret:bqca", "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	f.auth = nil
	if _, err := bqRunSQL(t, emu, Options{}, "select 1"); err != nil {
		t.Errorf("emulator: %v", err)
	}
	if strings.Join(f.auth, "") != "" {
		t.Errorf("a login went to the emulator: %q", f.auth)
	}
	if _, err := emu.ExecContext(context.Background(), "insert into t values (1)"); errCode(err) != "WRITE_REQUIRES_FLAG" {
		t.Errorf("emulator insert: %v", err)
	}
	if !bqGoogleHost("https://bigquery-x.p.googleapis.com") || bqGoogleHost("http://bigquery.googleapis.com") || bqGoogleHost("https://googleapis.com.evil.test") {
		t.Error("bqGoogleHost")
	}
}

// --write runs a write alone as a job; --dry-run is BigQuery's own dry
// run, for reads too, and runs nothing.
func TestBigQueryWrite(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	rw, err := openBQ(t, bqTestURL, "", false, dial)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bqRunSQL(t, rw, Options{Write: true}, "insert into shop.t values (1)")
	if err != nil || *res.Results[0].RowsAffected != 3 || !res.Committed {
		t.Fatalf("insert: %+v %v", res, err)
	}
	n := len(f.jobs)
	for _, q := range []string{"insert into shop.t values (2)", "select 1"} {
		res, err = bqRunSQL(t, rw, Options{Write: true, DryRun: true}, q)
		if err != nil || res.Committed || !strings.Contains(res.Results[0].Skipped, "without running it") || *res.Results[0].BytesProcessed != 1234 {
			t.Errorf("dry run of %s: %+v %v", q, res, err)
		}
	}
	if len(f.jobs) != n {
		t.Errorf("a dry run ran a job: %v", f.jobs[n:])
	}
	if _, err := bqRunSQL(t, rw, Options{Write: true, DryRun: true}, "insert into huge values (1)"); errCode(err) != "DB_BYTES_LIMIT" {
		t.Errorf("dry run over the cap: %v", err)
	}
	// db explain: the dry run as rows, for a write too
	plan, _ := driver.ClassifySQL("bigquery", "delete from shop.t where id = 1")
	res, err = Run(context.Background(), rw, "bigquery", driver.PlanOnly(plan), Options{Showplan: "text", Limit: 100})
	if err != nil || len(f.jobs) != n {
		t.Fatalf("explain: %v", err)
	}
	text := fmt.Sprint(res.Results[0].Rows)
	for _, want := range []string{"DELETE", "1.2 KiB (1234 bytes)", "within --max-bytes 10.0 GiB", "my-project.shop.orders", "n INT64"} {
		if !strings.Contains(text, want) {
			t.Errorf("explain lacks %q: %s", want, text)
		}
	}
	// a script where komando saw one statement does not run, even with --write
	if _, err := bqRunSQL(t, rw, Options{Write: true}, "insert into shop.t values (1) -- script"); errCode(err) != "USAGE" || len(f.jobs) != n {
		t.Errorf("script: %v", err)
	}
	// CALL runs as a script, rated sql-opaque
	if _, err := bqRunSQL(t, rw, Options{Write: true}, "call shop.proc()"); err != nil {
		t.Errorf("call: %v", err)
	}
}

func TestBigQueryValues(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	db, err := openBQ(t, bqTestURL, "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	res, err := bqRunSQL(t, db, Options{}, "select values")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Results[0]
	b, _ := json.Marshal(r.Rows[0])
	want := `["9007199254740993",2.5,true,"2024-01-01T00:00:00.123456Z",{"base64":"SGk="},"123456789012345678.123456789",{"a":[1,2.5,"12345678901234567890"]},"2024-01-01",["x","y"],{"a":7,"b":"z"},null,"Infinity"]`
	if string(b) != want {
		t.Errorf("values:\n%s\nwant\n%s", b, want)
	}
	if r.Columns[0].Type != "int64" || r.Columns[8].Type != "array<string>" || r.Columns[9].Type != "struct" {
		t.Errorf("types: %+v", r.Columns)
	}
	res, err = bqRunSQL(t, db, Options{}, "select pages")
	if err != nil || res.Results[0].RowCount != 3 {
		t.Errorf("pages: %+v %v", res, err)
	}
	if v := bqValue("1.6e9", bqField{Type: "TIMESTAMP"}); v != "2020-09-13T12:26:40Z" {
		t.Errorf("float timestamp: %v", v)
	}
}

// A run that times out cancels its job on the server.
func TestBigQueryCancel(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	db, err := openBQ(t, bqTestURL, "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	old := bqPoll
	bqPoll = 20 * time.Millisecond
	t.Cleanup(func() { bqPoll = old })
	if _, err := bqRunSQL(t, db, Options{Timeout: 300 * time.Millisecond}, "select slow"); errCode(err) != "TIMEOUT" {
		t.Errorf("slow: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cancels) != 1 || !strings.HasPrefix(f.cancels[0], "komando_") || !strings.HasSuffix(f.cancels[0], "@EU") {
		t.Errorf("cancels: %v", f.cancels)
	}
}

func TestBigQueryErrors(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	db, err := openBQ(t, bqTestURL, "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	for q, code := range map[string]string{"select bad": "DB_ERROR", "select * from missing": "DB_ERROR", "select denied": "DB_PRIVILEGE"} {
		if _, err := bqRunSQL(t, db, Options{}, q); errCode(err) != code {
			t.Errorf("%s: %v, want %s", q, err, code)
		}
	}
	for _, c := range []struct {
		e    *bqError
		code string
	}{
		{&bqError{Status: 401}, "DB_AUTH"},
		{&bqError{Status: 400, Reason: "bytesBilledLimitExceeded"}, "DB_BYTES_LIMIT"},
		{&bqError{Status: 403, Reason: "quotaExceeded"}, "DB_ERROR"},
		{&bqError{Status: 400, Reason: "stopped"}, "DB_ERROR"},
		{&bqError{Status: 400, Reason: "timeout"}, "TIMEOUT"},
		{&bqError{Status: 403, Reason: "responseTooLarge"}, "DB_ERROR"}, // BigQuery sends it with 403
		{&bqError{Status: 400, Reason: "responseTooLarge"}, "DB_ERROR"},
		{&bqError{Status: 403, Reason: "billingNotEnabled"}, "DB_ERROR"},
		{&bqError{Status: 403, Reason: "accessDenied"}, "DB_PRIVILEGE"},
		{&bqError{Status: 403}, "DB_PRIVILEGE"},
	} {
		if got := errCode(bigqueryErr(c.e)); got != c.code {
			t.Errorf("%+v: %s, want %s", c.e, got, c.code)
		}
	}
	for reason, hint := range map[string]string{"responseTooLarge": "add LIMIT", "billingNotEnabled": "billing"} {
		var oe *out.Error
		if !errors.As(bigqueryErr(&bqError{Status: 403, Reason: reason}), &oe) || !strings.Contains(oe.Hint, hint) {
			t.Errorf("%s: hint %+v, want %q in it", reason, oe, hint)
		}
	}
	if !bqRetry(&bqError{Status: 503}) || bqRetry(&bqError{Status: 400}) || !bqRetry(&bqError{Status: 400, Reason: "backendError"}) {
		t.Error("retry")
	}
	if e := bqFailure(502, []byte("<html>bad gateway</html>")).Error(); e != "<html>bad gateway</html>" {
		t.Errorf("not JSON: %s", e)
	}
}

func TestBigQueryOps(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	db, err := openBQ(t, "bigquery://my-project/shop?ca=secret:bqca", "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	info, err := Info(ctx, db, "bigquery", time.Minute)
	if err != nil || info["location"] != "EU" || info["datasets"] != 2 || info["user"] != "sa@my-project.iam.gserviceaccount.com" {
		t.Errorf("info: %v %v", info, err)
	}
	rows, err := Activity(ctx, db, "bigquery", false, time.Minute)
	if err != nil || len(rows) != 1 || rows[0]["pid"] != sfPID("bquxjob_1") {
		t.Fatalf("activity: %v %v", rows, err)
	}
	if q := f.queries[fmt.Sprint(f.jobs[len(f.jobs)-1]["jobReference"].(map[string]any)["jobId"])]; !strings.Contains(q, "`region-eu`.INFORMATION_SCHEMA.JOBS") {
		t.Errorf("activity query: %s", q)
	}
	if err := Kill(ctx, db, "bigquery", sfPID("bquxjob_1"), false); err != nil || len(f.cancels) != 1 || f.cancels[0] != "bquxjob_1@eu" {
		t.Errorf("kill: %v %v", err, f.cancels)
	}
	if err := Kill(ctx, db, "bigquery", 1, false); errCode(err) != "SESSION_NOT_FOUND" {
		t.Errorf("kill unknown: %v", err)
	}
	if err := Kill(ctx, db, "bigquery", 1, true); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("kill --session: %v", err)
	}
	sizes, err := Sizes(ctx, db, "bigquery", 10, time.Minute)
	if err != nil || fmt.Sprint(sizes["databases"]) != "[map[bytes:4096 name:shop]]" {
		t.Errorf("sizes: %v %v", sizes, err)
	}
	if _, err := Locks(ctx, db, "bigquery", time.Minute); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("locks: %v", err)
	}
	if _, err := Users(ctx, db, "bigquery", time.Minute); errCode(err) != "NOT_SUPPORTED" {
		t.Errorf("users: %v", err)
	}
}

func TestBigQuerySchema(t *testing.T) {
	f := &fakeBQ{}
	dial, _ := bqServer(t, f)
	db, err := openBQ(t, "bigquery://my-project?ca=secret:bqca", "", true, dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tables, err := Schema(ctx, db, "bigquery", nil, time.Minute)
	if err != nil || len(tables) != 4 || tables[1].Name != "big_orders" || tables[1].Type != "view" || tables[2].Name != "returns" || tables[3].Schema != "logs" {
		t.Fatalf("list: %+v %v", tables, err)
	}
	tables, err = Schema(ctx, db, "bigquery", []string{"shop.orders"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tables[0])
	want := `{"schema":"shop","name":"orders","type":"table","row_estimate":42,"columns":[{"name":"id","type":"INT64","nullable":false,"primary_key":true},` +
		`{"name":"item","type":"STRING","nullable":true},{"name":"addr","type":"STRUCT","nullable":true},{"name":"addr.city","type":"STRING","nullable":true},` +
		`{"name":"tags","type":"ARRAY\u003cSTRING\u003e","nullable":true}],"indexes":[{"name":"partition by","definition":"PARTITION BY DAY(placed)"},` +
		`{"name":"cluster by","definition":"CLUSTER BY item"}]}`
	if string(b) != want {
		t.Errorf("orders:\n%s\nwant\n%s", b, want)
	}
	if _, err := Schema(ctx, db, "bigquery", []string{"shop.nope"}, time.Minute); errCode(err) != "TABLE_NOT_FOUND" {
		t.Errorf("missing: %v", err)
	}
	if _, err := Schema(ctx, db, "bigquery", []string{"orders"}, time.Minute); errCode(err) != "USAGE" {
		t.Errorf("no dataset: %v", err)
	}
	if _, err := Schema(ctx, db, "bigquery", []string{"a.b.c.d"}, time.Minute); errCode(err) != "USAGE" {
		t.Errorf("four parts: %v", err)
	}
	if tables, err := Schema(ctx, db, "bigquery", []string{"`my-project.shop.orders`"}, time.Minute); err != nil || tables[0].Schema != "shop" {
		t.Errorf("full name: %+v %v", tables, err)
	}
}

func TestBigQueryHelpers(t *testing.T) {
	for in, want := range map[string]int64{"10GB": 10 << 30, "500MiB": 500 << 20, "1TB": 1 << 40, "1.5K": 1536, "123": 123, "0": 0, "7B": 7, " 2 gb ": 2 << 30} {
		if got, err := ParseBytes(in); err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GB", "-1GB", "ten", "1e30TB"} {
		if _, err := ParseBytes(in); err == nil {
			t.Errorf("ParseBytes(%q) took it", in)
		}
	}
	if l := bqLabel("komando/" + strings.Repeat("Ab.", 30)); len(l) != 63 || strings.ContainsAny(l, "A.") {
		t.Errorf("label: %s", l)
	}
	if humanBytes(10<<30) != "10.0 GiB" || humanBytes(12) != "12 B" {
		t.Error("humanBytes")
	}
}
