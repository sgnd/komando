package registry

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/proxyx/proxytest"
)

// Behind a company proxy (HTTPS_PROXY), the registry is reached through
// the proxy's tunnel, with the certificate still checked against the
// registry's name. NO_PROXY and a --via path skip the proxy.
func TestRegistryThroughProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pool, err := CAPool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	p := proxytest.Start(t, srv.Listener.Addr().String(), http.StatusOK)
	t.Setenv("HTTPS_PROXY", p.URL)
	t.Setenv("NO_PROXY", "")
	ctx := context.Background()

	if err := New("example.com", TLS{RootCAs: pool}, "", "", nil).Ping(ctx); err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	if h := p.Hosts(); !slices.Equal(h, []string{"example.com:443"}) {
		t.Fatalf("proxy was asked for %v", h)
	}

	t.Setenv("NO_PROXY", ".invalid") // a name that never resolves: no real network
	err = New("registry.invalid", TLS{RootCAs: pool}, "", "", nil).Ping(ctx)
	if len(p.Hosts()) != 1 || err == nil {
		t.Errorf("NO_PROXY: proxy asked %v, err %v; want a direct (failing) dial", p.Hosts(), err)
	}

	t.Setenv("NO_PROXY", "")
	via := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	if err := New("example.com", TLS{RootCAs: pool}, "", "", via).Ping(ctx); err != nil {
		t.Fatalf("through --via: %v", err)
	}
	if len(p.Hosts()) != 1 {
		t.Errorf("a --via path must not use the proxy, it was asked for %v", p.Hosts())
	}
}
