// Command bigquery is a stand-in for BigQuery's REST API and Google's
// token endpoint in the end-to-end lab: no Google project is at hand, and
// the free emulator cannot do dry runs. It serves HTTPS on :443 with a
// certificate from its own CA for bigquery.e2e.internal (reached through
// bastion, which resolves the lab alias), takes service account logins
// for the key it writes, answers dry runs and a few statements, and logs
// every job that runs (dry runs are not logged). It writes /e2e/ca.crt,
// the service account key /e2e/sa.json and the log /e2e/jobs.log, which
// the checks read with docker compose exec.
//
// It checks komando's side of the protocol (login, TLS, --via, dry runs,
// what is sent and what never is), not BigQuery's SQL.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	host    = "bigquery.e2e.internal"
	project = "e2e-project"
	token   = "e2e-access-token-1"
)

// dir and addr can be changed to run the fake outside its container.
var dir, addr = env("BIGQUERY_FAKE_DIR", "/e2e"), env("BIGQUERY_FAKE_ADDR", ":443")

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type server struct {
	sa    *rsa.PublicKey
	mu    sync.Mutex
	jobs  map[string]string // job ID: its answer
	plain bool              // BIGQUERY_FAKE_PLAIN: http, no login (a run outside the lab)
}

func main() {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	caKey, caCert, caDER := must3(newCA())
	leafKey := must(rsa.GenerateKey(rand.Reader, 2048))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bigquery e2e"},
		DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER := must(x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey))
	write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	saKey := must(rsa.GenerateKey(rand.Reader, 2048))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(saKey))})
	write("sa.json", must(json.Marshal(map[string]string{"type": "service_account", "project_id": project, "private_key_id": "e2e-1",
		"private_key": string(keyPEM), "client_email": "e2e@" + project + ".iam.gserviceaccount.com", "token_uri": "https://" + host + "/token"})))
	write("jobs.log", nil)
	s := &server{sa: &saKey.PublicKey, jobs: map[string]string{}, plain: os.Getenv("BIGQUERY_FAKE_PLAIN") != ""}
	srv := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}}
	if s.plain {
		log.Fatal(srv.ListenAndServe())
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func newCA() (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "komando e2e bigquery CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, der, err
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func must3[A, B, C any](a A, b B, c C, err error) (A, B, C) {
	if err != nil {
		log.Fatal(err)
	}
	return a, b, c
}

func write(name string, b []byte) {
	if err := os.WriteFile(dir+"/"+name, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

// grant checks the service account's signed assertion (RS256) and gives
// the access token.
func (s *server) grant(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p := strings.Split(r.Form.Get("assertion"), ".")
	ok := len(p) == 3
	if ok {
		sig, _ := base64.RawURLEncoding.DecodeString(p[2])
		sum := sha256.Sum256([]byte(p[0] + "." + p[1]))
		ok = rsa.VerifyPKCS1v15(s.sa, crypto.SHA256, sum[:], sig) == nil
	}
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
		return
	}
	fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, token)
}

func fail(w http.ResponseWriter, status int, reason, msg string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%d,"message":%q,"errors":[{"reason":%q,"message":%q}]}}`, status, msg, reason, msg)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/token" {
		s.grant(w, r)
		return
	}
	if !s.plain && r.Header.Get("Authorization") != "Bearer "+token {
		fail(w, http.StatusUnauthorized, "required", "Request is missing required authentication credential.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/projects/"+project)
	switch {
	case r.Method == http.MethodPost && path == "/jobs":
		var job struct {
			JobReference  struct{ JobID string } `json:"jobReference"`
			Configuration struct {
				DryRun bool `json:"dryRun"`
				Query  struct {
					Query           string `json:"query"`
					QueryParameters []struct {
						ParameterValue struct{ Value string } `json:"parameterValue"`
					} `json:"queryParameters"`
				} `json:"query"`
			} `json:"configuration"`
		}
		if json.NewDecoder(r.Body).Decode(&job) != nil {
			fail(w, http.StatusBadRequest, "invalid", "not JSON")
			return
		}
		q := job.Configuration.Query
		var params []string
		for _, p := range q.QueryParameters {
			params = append(params, p.ParameterValue.Value)
		}
		low := strings.ToLower(strings.Join(strings.Fields(q.Query), " "))
		if job.Configuration.DryRun {
			dryRun(w, low)
			return
		}
		if f, err := os.OpenFile(dir+"/jobs.log", os.O_APPEND|os.O_WRONLY, 0); err == nil {
			fmt.Fprintln(f, low)
			f.Close()
		}
		s.jobs[job.JobReference.JobID] = answer(low, params)
		fmt.Fprintf(w, `{"jobReference":{"projectId":%q,"jobId":%q,"location":"EU"},"status":{"state":"DONE"}}`, project, job.JobReference.JobID)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/queries/"):
		res, ok := s.jobs[strings.TrimPrefix(path, "/queries/")]
		if !ok {
			fail(w, http.StatusNotFound, "notFound", "Not found: Job")
			return
		}
		fmt.Fprint(w, res)
	case r.Method == http.MethodGet && path == "/datasets":
		fmt.Fprint(w, `{"datasets":[{"datasetReference":{"datasetId":"shop","projectId":"e2e-project"}}]}`)
	case r.Method == http.MethodGet && path == "/datasets/shop":
		fmt.Fprint(w, `{"location":"EU"}`)
	case r.Method == http.MethodGet && path == "/datasets/shop/tables":
		fmt.Fprint(w, `{"tables":[{"tableReference":{"tableId":"orders"},"type":"TABLE"}]}`)
	case r.Method == http.MethodGet && path == "/datasets/shop/tables/orders":
		fmt.Fprint(w, `{"type":"TABLE","numRows":"2","schema":{"fields":[{"name":"id","type":"INTEGER","mode":"REQUIRED"},{"name":"item","type":"STRING"}]},
			"clustering":{"fields":["id"]}}`)
	default:
		fail(w, http.StatusNotFound, "notFound", "Not found: "+r.URL.Path)
	}
}

// dryRun answers a dry run: the statement type, and the bytes the query
// would read (50 GiB for a query that names huge_events).
func dryRun(w http.ResponseWriter, low string) {
	types := map[string]string{"select": "SELECT", "with": "SELECT", "insert": "INSERT", "delete": "DELETE", "drop": "DROP_TABLE", "create": "CREATE_TABLE"}
	st := types[strings.SplitN(low, " ", 2)[0]]
	if strings.Contains(low, "sneaky") {
		st = "INSERT" // BigQuery sees a write where komando saw a read
	}
	if st == "" {
		fail(w, http.StatusBadRequest, "invalidQuery", "Syntax error: the komando e2e fake does not know this statement")
		return
	}
	bytes := "1024"
	if strings.Contains(low, "huge_events") {
		bytes = fmt.Sprint(int64(50) << 30)
	}
	fmt.Fprintf(w, `{"jobReference":{"projectId":%q,"location":"EU"},"statistics":{"totalBytesProcessed":%q,"query":{"statementType":%q,"totalBytesProcessed":%q}},"status":{"state":"DONE"}}`,
		project, bytes, st, bytes)
}

// answer is a finished job's results.
func answer(low string, params []string) string {
	switch {
	case strings.HasPrefix(low, "select ? as greeting"):
		b, _ := json.Marshal(params[0])
		return `{"jobComplete":true,"totalBytesProcessed":"0","schema":{"fields":[{"name":"greeting","type":"STRING"},{"name":"n","type":"INTEGER"}]},"rows":[{"f":[{"v":` +
			string(b) + `},{"v":"42"}]}]}`
	case strings.HasPrefix(low, "insert"):
		return `{"jobComplete":true,"numDmlAffectedRows":"2","totalBytesProcessed":"0"}`
	case strings.Contains(low, "huge_events"):
		return `{"jobComplete":true,"totalBytesProcessed":"53687091200","schema":{"fields":[{"name":"n","type":"INTEGER"}]},"rows":[{"f":[{"v":"7"}]}]}`
	}
	return `{"jobComplete":true,"totalBytesProcessed":"1024","schema":{"fields":[{"name":"x","type":"STRING"}]},"rows":[{"f":[{"v":"BigQuery"}]}]}`
}
