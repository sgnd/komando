package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Only the pinned host:port is sent elsewhere, through the dialer it wraps
// (the --via path); other hosts and ports are dialed as given.
func TestPinDial(t *testing.T) {
	var got []string
	via := func(ctx context.Context, network, addr string) (net.Conn, error) {
		got = append(got, addr)
		return nil, errors.New("not connected")
	}
	dial := pinDial(via, "registry.example.com:443", "104.248.148.41:443")
	for _, addr := range []string{"registry.example.com:443", "Registry.Example.COM.:443", "registry.example.com:5000", "auth.example.com:443", "104.248.148.41:443"} {
		_, _ = dial(context.Background(), "tcp", addr)
	}
	want := []string{"104.248.148.41:443", "104.248.148.41:443", "registry.example.com:5000", "auth.example.com:443", "104.248.148.41:443"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
	if pinDial(nil, "registry.example.com:443", "") != nil {
		t.Error("no resolve option: a direct connection should stay nil")
	}
	got = nil
	_, _ = pinDial(via, "registry.example.com:443", "")(context.Background(), "tcp", "registry.example.com:443")
	if fmt.Sprint(got) != "[registry.example.com:443]" {
		t.Errorf("no resolve option: dialed %v", got)
	}
}

// A registry whose certificate names only registry.test (no IP), reached
// at 127.0.0.1 with ?resolve=: `conn test` and the registry client both
// connect to the IP, the token request to the same host does too, and TLS
// still sends and checks the name, against the ca= secret.
func TestRegistryResolve(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "a passphrase long enough for tests")
	caPEM, leaf := testRegistryCert(t, "registry.test")
	if err := vault.Set("reg-ca", string(caPEM)); err != nil {
		t.Fatal(err)
	}
	if err := vault.Set("reg-pw", "s3cret"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string // "SNI Host path" of every request
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.ServerName+" "+r.Host+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			if u, p, _ := r.BasicAuth(); u != "me" || p != "s3cret" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprint(w, `{"token":"t1"}`)
		case r.Header.Get("Authorization") != "Bearer t1":
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://`+r.Host+`/token",service="registry.test"`)
			w.WriteHeader(401)
		default:
			fmt.Fprint(w, "{}")
		}
	})
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshakes below
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	st := testConnState()
	conn := func(url string) *store.Conn {
		c := &store.Conn{Name: "reg", Kind: "registry", URL: url, PasswordRef: "secret:reg-pw"}
		st.Conns["reg"] = c
		return c
	}
	ctx := context.Background()

	// registry.test does not resolve anywhere: every connection must go to the IP
	c := conn("registry://me@registry.test:" + port + "?ca=secret:reg-ca&resolve=127.0.0.1")
	if r := testConn(ctx, st, c); !r.OK || r.Check != "login" {
		t.Fatalf("conn test: %+v %+v", r, r.Error)
	}
	rg, closeRG, err := openRegistry(ctx, st, c)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRG()
	mu.Lock()
	seen = nil
	mu.Unlock()
	if err := rg.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	host := "registry.test:" + port
	want := fmt.Sprint([]string{"registry.test " + host + " /v2/", "registry.test " + host + " /token", "registry.test " + host + " /v2/"})
	if fmt.Sprint(seen) != want {
		t.Errorf("requests (SNI Host path) %v, want %v", seen, want)
	}

	// the check stays on: without ca= the private CA is unknown, and
	// another name in the URL does not match the certificate
	for url, wantErr := range map[string]any{
		"registry://me@registry.test:" + port + "?resolve=127.0.0.1":                  &tls.CertificateVerificationError{},
		"registry://me@other.test:" + port + "?ca=secret:reg-ca&resolve=127.0.0.1":    x509.HostnameError{},
		"registry://me@127.0.0.1:" + port + "?ca=secret:reg-ca":                       x509.HostnameError{}, // why resolve is needed: no IP on the certificate
		"registry://me@registry.test:" + port + "?ca=secret:reg-ca&resolve=127.0.0.1": nil,
	} {
		rg, closeRG, err := openRegistry(ctx, st, conn(url))
		if err != nil {
			t.Fatal(err)
		}
		err = rg.Ping(ctx)
		closeRG()
		var refused *tls.CertificateVerificationError // the error type differs per OS without a CA pool
		var wrongName x509.HostnameError
		switch wantErr.(type) {
		case nil:
			if err != nil {
				t.Errorf("%s: %v", url, err)
			}
		case *tls.CertificateVerificationError:
			if !errors.As(err, &refused) {
				t.Errorf("%s: %v, want the certificate refused", url, err)
			}
		case x509.HostnameError:
			if !errors.As(err, &wrongName) {
				t.Errorf("%s: %v, want a host name error", url, err)
			}
		}
	}
}

// ?tls=skip-verify with ?resolve=, the way a server does it with
// /etc/hosts plus Docker's insecure-registries: the name in the URL is a
// local name whose public DNS points elsewhere, and the certificate (an
// unknown CA, issued for another name) is accepted. `conn test` and
// `registry ls` work, every connection goes to the IP, the name is still
// sent, and nothing in the output pushes ca=.
func TestRegistryResolveSkipVerify(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "a passphrase long enough for tests")
	_, leaf := testRegistryCert(t, "registry.test")
	if err := vault.Set("reg-pw", "s3cret"); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string // "SNI Host" of every request
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.TLS.ServerName+" "+r.Host)
		mu.Unlock()
		if u, p, _ := r.BasicAuth(); u != "me" || p != "s3cret" { // nginx in front of registry:2
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v2/_catalog" {
			fmt.Fprint(w, `{"repositories":["team/app"]}`)
			return
		}
		fmt.Fprint(w, "{}")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // conn test's port check closes without a handshake
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	// codeoffice.test is not on the certificate and resolves nowhere
	url := "registry://me@codeoffice.test:" + port + "?tls=skip-verify&resolve=127.0.0.1"
	if _, err := runCache(t, "-o", "json", "conn", "add", "reg", url, "--password-ref", "secret:reg-pw"); err != nil {
		t.Fatal(err)
	}
	test, err := runCache(t, "-o", "json", "test", "reg")
	if err != nil || !strings.Contains(test, `"check":"login"`) {
		t.Fatalf("test: %v\n%s", err, test)
	}
	ls, err := runCache(t, "-o", "json", "registry", "ls", "reg")
	if err != nil || !strings.Contains(ls, "team/app") {
		t.Fatalf("registry ls: %v\n%s", err, ls)
	}
	if strings.Contains(test+ls, "ca=") {
		t.Errorf("output suggests ca=:\n%s\n%s", test, ls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) < 2 {
		t.Fatalf("requests: %v", seen)
	}
	for _, s := range seen {
		if s != "codeoffice.test codeoffice.test:"+port {
			t.Errorf("request with SNI and Host %q, want the name codeoffice.test", s)
		}
	}
}

// `conn test` on an s3 conn connects to the resolve address too.
func TestS3ResolveConnTest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	st := testConnState()
	c := &store.Conn{Name: "minio", Kind: "s3", URL: "s3://KEY@backups?endpoint=https://minio.test:" + port + "&resolve=127.0.0.1"}
	st.Conns[c.Name] = c
	if r := testConn(context.Background(), st, c); !r.OK || r.Check != "tcp" {
		t.Fatalf("conn test: %+v %+v", r, r.Error)
	}
}

// testRegistryCert makes a CA and a server certificate it signed for name
// only (a DNS name, no IP address), like mkcert does for one host name.
func testRegistryCert(t *testing.T, name string) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
