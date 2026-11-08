package cachex

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// privateCA makes a CA and a server certificate for 127.0.0.1 signed by it.
func privateCA(t *testing.T) (caPEM string, server tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "cache"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A memcached over TLS whose certificate a private CA signed: refused with
// this computer's CAs, accepted with ?ca= naming that CA.
func TestMemcachedPrivateCA(t *testing.T) {
	caPEM, cert := privateCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
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
			go func() {
				defer c.Close()
				c.(*tls.Conn).Handshake()
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					c.Write([]byte("VERSION 1.6.39\r\n"))
				}
			}()
		}
	}()
	saved := driver.ResolveSecret
	driver.ResolveSecret = func(ref string) (string, error) { return caPEM, nil }
	defer func() { driver.ResolveSecret = saved }()
	ctx := context.Background()

	plain, _ := driver.Parse("memcacheds://" + ln.Addr().String())
	if _, err := openMemcache(ctx, plain, "", nil, 5*time.Second); err == nil || !strings.Contains(err.(*out.Error).Message+err.(*out.Error).Hint, "certificate") {
		t.Errorf("without the CA: %v", err)
	}
	withCA, err := driver.Parse("memcacheds://" + ln.Addr().String() + "?ca=secret:cache-ca")
	if err != nil {
		t.Fatal(err)
	}
	m, err := openMemcache(ctx, withCA, "", nil, 5*time.Second)
	if err != nil {
		t.Fatalf("with ?ca=: %v", err)
	}
	m.Close()
}
