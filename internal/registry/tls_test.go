package registry

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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// A registry that sends only its leaf certificate, issued by a CA nobody
// has (mkcert on another machine): the leaf itself as ca= pins it. The
// leaf is not a CA (no basicConstraints) and that is fine; the name and
// dates are still checked.
func TestLeafPinnedAsCA(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mkcert someone@elsewhere"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{OrganizationalUnit: []string{"mkcert development certificate"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"registry.example.test"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	ctx := context.Background()
	pool, err := CAPool(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	if err != nil {
		t.Fatal(err)
	}
	if err := New("registry.example.test", TLS{}, "", "", dial).Ping(ctx); err == nil {
		t.Fatal("default: accepted a certificate from an unknown CA")
	}
	if err := New("registry.example.test", TLS{RootCAs: pool}, "", "", dial).Ping(ctx); err != nil {
		t.Fatalf("leaf pinned as ca=: %v", err)
	}
	if err := New("other.example.test", TLS{RootCAs: pool}, "", "", dial).Ping(ctx); err == nil {
		t.Error("leaf pinned as ca=: accepted another name")
	}
	// another leaf from the same CA is not trusted: only the pinned one is
	otherDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(3),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"registry.example.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, caCert, &leafKey.PublicKey, caKey)
	srv.TLS.Certificates[0].Certificate = [][]byte{otherDER}
	if err := New("registry.example.test", TLS{RootCAs: pool}, "", "", dial).Ping(ctx); err == nil {
		t.Error("leaf pinned as ca=: accepted a different leaf")
	}
}
