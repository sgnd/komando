package transport

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A person's HTTPS_PROXY is used; once the environment is an AI agent's
// (DistrustEnv), no proxy comes from it.
func TestProxyNotFromAnAgentsEnv(t *testing.T) {
	undo := func() {}
	t.Cleanup(func() { undo() })
	t.Setenv("HTTPS_PROXY", "http://proxy.example.com:3128")
	t.Setenv("NO_PROXY", "")
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "vpn.example.com"}}
	if u, err := Proxy()(req); err != nil || u == nil || u.Host != "proxy.example.com:3128" {
		t.Fatalf("a person's proxy: %v %v", u, err)
	}
	undo = DistrustEnv()
	if u, err := Proxy()(req); err != nil || u != nil {
		t.Fatalf("an agent's proxy was taken: %v %v", u, err)
	}
}

// helperEnv makes this test binary a client that dials the address in it
// with Go's default trust (RootCAs nil).
const helperEnv = "KOMANDO_TRANSPORT_TLS_HELPER"

func TestMain(m *testing.M) {
	if addr := os.Getenv(helperEnv); addr != "" {
		c, err := tls.Dial("tcp", addr, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com"})
		if err == nil {
			c.Close()
			os.Stdout.WriteString("TRUSTED\n")
			os.Exit(0)
		}
		os.Stdout.WriteString("REFUSED " + err.Error() + "\n")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// SSL_CERT_FILE and SSL_CERT_DIR set when komando starts must not make it
// trust a CA: on Linux, and on macOS since Go 1.27, Go took the CAs from
// them, so an AI agent's own CA (with its proxy) read stored logins. The
// check runs in a new process, since Go reads them once.
func TestEnvCAIsIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "agent-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		c := exec.CommandContext(ctx, os.Args[0])
		c.Env = append(os.Environ(), append(env, helperEnv+"="+srv.Listener.Addr().String())...)
		b, err := c.Output()
		if err != nil {
			t.Fatalf("helper: %v %s", err, b)
		}
		return string(b)
	}
	for _, env := range [][]string{{"SSL_CERT_FILE=" + ca}, {"SSL_CERT_DIR=" + dir}} {
		if got := run(env...); !strings.HasPrefix(got, "REFUSED") {
			t.Errorf("%v: the server signed by that CA was trusted: %s", env, got)
		}
	}
	// the CA file itself is good: with it as RootCAs the server passes
	pool := Roots()
	b, _ := os.ReadFile(ca)
	pool.AppendCertsFromPEM(b)
	c, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "example.com", RootCAs: pool})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	c.Close()
}
