package sslvpn

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/proxyx/proxytest"
)

// Behind a company proxy, the portal login and the tunnel both go through
// HTTPS_PROXY; with a --via path (Options.Dial) neither does.
func TestPortalAndTunnelThroughProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := proxytest.Start(t, srv.Listener.Addr().String(), http.StatusOK)
	t.Setenv("HTTPS_PROXY", p.URL)
	t.Setenv("NO_PROXY", "")
	o := Options{CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
	u, _ := url.Parse("https://vpn.example.com")

	hc, err := httpClient(o, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Get(u.String())
	if err != nil {
		t.Fatalf("portal through the proxy: %v", err)
	}
	resp.Body.Close()
	c, err := dialTLS(context.Background(), o, u)
	if err != nil {
		t.Fatalf("tunnel through the proxy: %v", err)
	}
	c.Close()
	if h := p.Hosts(); !slices.Equal(h, []string{"vpn.example.com:443", "vpn.example.com:443"}) {
		t.Errorf("proxy was asked for %v", h)
	}

	o.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	if c, err = dialTLS(context.Background(), o, u); err != nil {
		t.Fatalf("tunnel through --via: %v", err)
	}
	c.Close()
	if hc, _ = httpClient(o, "vpn.example.com"); hc.Transport.(*http.Transport).Proxy != nil {
		t.Error("a --via portal must not use the proxy")
	}
	if len(p.Hosts()) != 2 {
		t.Errorf("--via must not use the proxy, it was asked for %v", p.Hosts())
	}
}
