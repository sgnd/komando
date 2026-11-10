// Command snowflake is a stand-in for Snowflake's SQL API in the
// end-to-end lab: no Snowflake account or emulator is free to run there.
// It serves HTTPS on :443 with a certificate from its own CA for
// *.snowflakecomputing.com (reached through bastion, which resolves the
// lab alias), takes key-pair logins for the user E2E of the account
// E2E-ACCT and the programmatic access token e2e-pat-1, answers a few
// statements asynchronously, and logs every statement it gets. It writes
// /e2e/ca.crt, the user's private key /e2e/user.key and the log
// /e2e/statements.log, which the checks read with docker compose exec.
//
// It checks komando's side of the protocol (login, TLS, --via, what is
// sent and what never is), not Snowflake's SQL.
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
	sub   = "E2E-ACCT.E2E"
	token = "e2e-pat-1"
)

// dir and addr can be changed to run the fake outside its container.
var dir, addr = env("SNOWFLAKE_FAKE_DIR", "/e2e"), env("SNOWFLAKE_FAKE_ADDR", ":443")

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type server struct {
	user    *rsa.PublicKey
	mu      sync.Mutex
	results map[string]string // handle: the answer when asked
	n       int
}

func main() {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	caKey, caCert, caDER := must3(newCA())
	leafKey := must(rsa.GenerateKey(rand.Reader, 2048))
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "snowflake e2e"},
		DNSNames: []string{"*.snowflakecomputing.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER := must(x509.CreateCertificate(rand.Reader, leaf, caCert, &leafKey.PublicKey, caKey))
	write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	userKey := must(rsa.GenerateKey(rand.Reader, 2048))
	write("user.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(userKey))}))
	write("statements.log", nil)
	s := &server{user: &userKey.PublicKey, results: map[string]string{}}
	srv := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func newCA() (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "komando e2e snowflake CA"},
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

// login checks the token: e2e-pat-1, or a key-pair JWT signed with the
// user's key for E2E-ACCT.E2E.
func (s *server) login(r *http.Request) bool {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch r.Header.Get("X-Snowflake-Authorization-Token-Type") {
	case "PROGRAMMATIC_ACCESS_TOKEN":
		return tok == token
	case "KEYPAIR_JWT":
		p := strings.Split(tok, ".")
		if len(p) != 3 {
			return false
		}
		sig, _ := base64.RawURLEncoding.DecodeString(p[2])
		sum := sha256.Sum256([]byte(p[0] + "." + p[1]))
		if rsa.VerifyPKCS1v15(s.user, crypto.SHA256, sum[:], sig) != nil {
			return false
		}
		raw, _ := base64.RawURLEncoding.DecodeString(p[1])
		var c struct {
			Iss, Sub string
			Exp      int64
		}
		der, _ := x509.MarshalPKIXPublicKey(s.user)
		fp := sha256.Sum256(der)
		return json.Unmarshal(raw, &c) == nil && c.Sub == sub && c.Iss == sub+".SHA256:"+base64.StdEncoding.EncodeToString(fp[:]) &&
			c.Exp > time.Now().Unix()
	}
	return false
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.login(r) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":"390144","message":"JWT token is invalid."}`)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/statements")
	switch {
	case r.Method == http.MethodPost && path == "":
		var body struct {
			Statement string                       `json:"statement"`
			Bindings  map[string]map[string]string `json:"bindings"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f, err := os.OpenFile(dir+"/statements.log", os.O_APPEND|os.O_WRONLY, 0)
		if err == nil {
			fmt.Fprintln(f, strings.Join(strings.Fields(body.Statement), " "))
			f.Close()
		}
		s.n++
		h := fmt.Sprintf("01e2e000-0000-0000-0000-%012d", s.n)
		s.results[h] = answer(body.Statement, body.Bindings)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"code":"333334","message":"Asynchronous execution in progress.","statementHandle":%q,"statementStatusUrl":"/api/v2/statements/%s"}`, h, h)
	case r.Method == http.MethodGet && s.results[strings.TrimPrefix(path, "/")] != "":
		res := s.results[strings.TrimPrefix(path, "/")]
		if strings.HasPrefix(res, `{"code":"0`) {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		fmt.Fprint(w, res)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func rows(cols []string, row ...string) string {
	var rt []string
	for _, c := range cols {
		name, typ, _ := strings.Cut(c, ":")
		rt = append(rt, fmt.Sprintf(`{"name":%q,"type":%q,"precision":38,"scale":0}`, name, typ))
	}
	b, _ := json.Marshal(row)
	return `{"resultSetMetaData":{"numRows":1,"rowType":[` + strings.Join(rt, ",") + `]},"data":[` + string(b) + `],"code":"090001"}`
}

// answer is what the fake says to a statement.
func answer(stmt string, bindings map[string]map[string]string) string {
	low := strings.ToLower(strings.TrimSpace(stmt))
	switch {
	case low == "select 1":
		return rows([]string{"1:fixed"}, "1")
	case strings.Contains(low, "current_version()"):
		return rows([]string{"v:text"}, "Snowflake 9.0.0 (komando e2e fake)")
	case strings.HasPrefix(low, "select ? as greeting"):
		return rows([]string{"GREETING:text", "N:fixed"}, bindings["1"]["value"], "42")
	case strings.HasPrefix(low, "insert"):
		return `{"resultSetMetaData":{"numRows":1,"rowType":[{"name":"number of rows inserted","type":"fixed"}]},"data":[["2"]],"stats":{"numRowsInserted":2}}`
	}
	return `{"code":"002003","message":"SQL compilation error: the komando e2e fake does not know this statement.","sqlState":"02000"}`
}
