package kube

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Relative certificate and token paths count from the kubeconfig's own
// folder, as kubectl reads them, whatever the current folder is.
func TestLoadRelativePaths(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("CA"), 0o600)
	os.WriteFile(filepath.Join(dir, "token"), []byte("tok\n"), 0o600)
	kc := `current-context: kind
clusters:
- name: kind
  cluster: {server: "https://127.0.0.1:6443", certificate-authority: ca.crt}
users:
- name: kind
  user: {tokenFile: token}
contexts:
- name: kind
  context: {cluster: kind, user: kind}
`
	p := filepath.Join(dir, "config")
	os.WriteFile(p, []byte(kc), 0o600)
	t.Chdir(t.TempDir())
	cfg, err := Load(os.ReadFile, p)
	if err != nil {
		t.Fatal(err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	b, err := x.Standalone()
	if err != nil {
		t.Fatalf("from another folder: %v", err)
	}
	if s := string(b); !strings.Contains(s, base64.StdEncoding.EncodeToString([]byte("CA"))) || !strings.Contains(s, "token: tok") {
		t.Errorf("standalone: %s", s)
	}
}

// A KUBECONFIG list is merged: the first file that names something wins.
func TestLoadMerges(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	a := write("a", "current-context: one\nclusters:\n- name: c\n  cluster: {server: \"https://a:1\"}\ncontexts:\n- name: one\n  context: {cluster: c}\n")
	b := write("b", "current-context: two\nclusters:\n- name: c\n  cluster: {server: \"https://b:1\"}\n- name: d\n  cluster: {server: \"https://d:1\"}\ncontexts:\n- name: two\n  context: {cluster: d}\n- name: one\n  context: {cluster: d}\n")
	cfg, err := Load(os.ReadFile, a, b)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CurrentContext != "one" || strings.Join(cfg.ContextNames(), ",") != "one,two" {
		t.Errorf("merged: %q %v", cfg.CurrentContext, cfg.ContextNames())
	}
	if x, _ := cfg.Resolve("one"); x.Cluster.Server != "https://a:1" {
		t.Errorf("the first file wins: %+v", x)
	}
	if _, err := Load(os.ReadFile, write("empty", "kind: Config\n")); err == nil {
		t.Error("no contexts at all is an error")
	}
}

// An object kind the cluster does not serve is an UnknownKindError; a
// discovery that could not reach the cluster is not, and is asked again.
func TestResourceForErrors(t *testing.T) {
	down := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/api/v1":
			w.Write([]byte(`{"resources":[{"name":"pods","kind":"Pod","namespaced":true}]}`))
		case "/apis":
			w.Write([]byte(`{"groups":[]}`))
		}
	}))
	defer srv.Close()
	x := &Context{}
	x.Cluster.Server = srv.URL
	c, err := New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	var uk *UnknownKindError
	if _, err := c.ResourceFor(context.Background(), "v1", "Pod"); err == nil || errors.As(err, &uk) {
		t.Errorf("a failed discovery is not an unknown kind: %v", err)
	}
	down = false
	if _, err := c.ResourceFor(context.Background(), "v1", "Pod"); err != nil {
		t.Errorf("discovery is asked again: %v", err)
	}
	if _, err := c.ResourceFor(context.Background(), "v1", "Widget"); !errors.As(err, &uk) || err.Error() != "the cluster does not serve v1 Widget" {
		t.Errorf("unknown kind: %v", err)
	}
}

// "." and ".." never reach the server as a name or namespace: pods/.. is
// the namespace itself, a DELETE there must not be sent.
func TestDotNamesRefused(t *testing.T) {
	sent := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent++ }))
	defer srv.Close()
	x := &Context{}
	x.Cluster.Server = srv.URL
	k, err := New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	pods := ResourceType{Path: "/api/v1", Name: "pods", Kind: "Pod", Namespaced: true}
	for _, p := range []string{pods.ObjectPath("shop", ".."), pods.ObjectPath("..", "web"), pods.ObjectPath("shop", ".")} {
		_, err := k.Do(context.Background(), "DELETE", p, nil, nil, "")
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != 400 {
			t.Errorf("%s: want a 400 before sending, got %v", p, err)
		}
	}
	if sent != 0 {
		t.Errorf("%d requests sent", sent)
	}
}

// With a CA in the kubeconfig the server is always checked against it,
// even when insecure-skip-tls-verify is set too (kubectl refuses the pair).
func TestCAWinsOverInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	x := &Context{}
	x.Cluster.Server = "https://10.255.255.1:6443"
	x.Cluster.InsecureSkipTLSVerify = true
	x.Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(ca)
	k, err := New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Error("a CA was given, yet the server's certificate is not checked")
	}
}
