package registry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A registry with a certificate from a private CA, reached by a name only
// the dialer knows (like a --via server's /etc/hosts): refused by default,
// trusted with its CA or with SkipVerify. The dialer gets the name, not an
// address, and the certificate check, SNI and Host header keep the name.
func TestTLSOptions(t *testing.T) {
	var sni, hostHeader string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sni, hostHeader = r.TLS.ServerName, r.Host
	}))
	srv.StartTLS()
	defer srv.Close()
	var dialed string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = addr
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	pool, err := CAPool(ca)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	err = New("example.com", TLS{}, "", "", dial).Ping(ctx)
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("default: %v, want an unknown authority error", err)
	}
	if err := New("example.com", TLS{RootCAs: pool}, "", "", dial).Ping(ctx); err != nil {
		t.Fatalf("with the CA: %v", err)
	}
	if dialed != "example.com:443" || sni != "example.com" || hostHeader != "example.com" {
		t.Errorf("dialed %q, SNI %q, Host %q; want the name example.com", dialed, sni, hostHeader)
	}
	if err := New("example.com", TLS{SkipVerify: true}, "", "", dial).Ping(ctx); err != nil {
		t.Fatalf("skip-verify: %v", err)
	}
	// the CA is only good for the names on the certificate
	err = New("registry.other.test", TLS{RootCAs: pool}, "", "", dial).Ping(ctx)
	var wrong x509.HostnameError
	if !errors.As(err, &wrong) {
		t.Errorf("another name: %v, want a host name error", err)
	}
	if _, err := CAPool([]byte("not a certificate")); err == nil {
		t.Error("CAPool accepted text without a certificate")
	}
}
