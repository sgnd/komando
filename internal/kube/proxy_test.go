package kube

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/proxyx/proxytest"
)

// Behind a company proxy the API server is reached through the proxy's
// tunnel: HTTPS_PROXY from the environment, or the kubeconfig's proxy-url,
// which wins, as with kubectl. The certificate is still checked against
// the server's name.
func TestAPIThroughProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/version" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"gitVersion":"v1.31.0"}`))
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	ctx := &Context{Name: "prod"}
	ctx.Cluster.Server = "https://example.com"
	ctx.Cluster.CertificateAuthorityData = base64.StdEncoding.EncodeToString(ca)
	ctx.User.Token = "tok"
	version := func(x *Context) error {
		c, err := New(x, nil)
		if err != nil {
			return err
		}
		var v struct{ GitVersion string }
		if err := c.Get(context.Background(), "/version", nil, &v); err != nil {
			return err
		}
		if v.GitVersion != "v1.31.0" {
			t.Errorf("version %q", v.GitVersion)
		}
		return nil
	}

	env := proxytest.Start(t, srv.Listener.Addr().String(), http.StatusOK)
	t.Setenv("HTTPS_PROXY", env.URL)
	t.Setenv("NO_PROXY", "")
	if err := version(ctx); err != nil {
		t.Fatalf("through HTTPS_PROXY: %v", err)
	}
	if h := env.Hosts(); !slices.Equal(h, []string{"example.com:443"}) {
		t.Fatalf("HTTPS_PROXY was asked for %v", h)
	}

	own := proxytest.Start(t, srv.Listener.Addr().String(), http.StatusOK)
	withURL := *ctx
	withURL.Cluster.ProxyURL = own.URL
	if err := version(&withURL); err != nil {
		t.Fatalf("through proxy-url: %v", err)
	}
	if len(own.Hosts()) != 1 || len(env.Hosts()) != 1 {
		t.Errorf("proxy-url wins: it was asked %v, HTTPS_PROXY %v", own.Hosts(), env.Hosts())
	}

	bad := *ctx
	bad.Cluster.ProxyURL = "proxy.corp:3128"
	if _, err := New(&bad, nil); err == nil || !strings.Contains(err.Error(), "proxy-url") {
		t.Errorf("a proxy-url without a scheme: %v", err)
	}
}

// exec and port-forward open their own connections (WebSocket, or SPDY on
// an older cluster); they go through the proxy too.
func TestStreamsThroughProxy(t *testing.T) {
	for _, old := range []bool{false, true} {
		kubelet := fakeKubelet(t, old)
		p := proxytest.Start(t, kubelet.Base.Host, http.StatusOK)
		x := &Context{Namespace: "shop"}
		x.Cluster.Server = "http://kube.example.com:8080"
		x.Cluster.ProxyURL = p.URL
		x.User.Token = "tok"
		c, err := New(x, nil)
		if err != nil {
			t.Fatal(err)
		}
		testExec(t, c)
		if h := p.Hosts(); len(h) == 0 || h[0] != "kube.example.com:8080" {
			t.Errorf("old=%v: proxy was asked for %v", old, h)
		}
	}
}

// Through a --via path, the path is the way out: no proxy.
func TestViaSkipsProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	x := &Context{}
	x.Cluster.Server = "https://example.com"
	x.Cluster.ProxyURL = "http://proxy.corp:3128"
	c, err := New(x, func(context.Context, string, string) (net.Conn, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if tr := c.http.Transport.(*http.Transport); tr.Proxy != nil {
		t.Error("a --via client must not use a proxy")
	}
}
