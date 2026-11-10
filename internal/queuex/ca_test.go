package queuex

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
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"

	"github.com/sgnd/komando/internal/driver"
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
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kafka"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Brokers whose certificate a private CA signed: refused with this
// computer's CAs, accepted with ?ca= naming that CA, with a SASL login on top.
func TestKafkaPrivateCA(t *testing.T) {
	caPEM, cert := privateCA(t)
	c := fakeCluster(t, kfake.TLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}),
		kfake.EnableSASL(), kfake.Superuser("PLAIN", "app", "s3cret"))
	saved := driver.ResolveSecret
	driver.ResolveSecret = func(string) (string, error) { return caPEM, nil }
	defer func() { driver.ResolveSecret = saved }()
	addr := c.ListenAddrs()[0]

	plain, _ := driver.Parse("kafka://app@" + addr + "?tls=true&sasl=plain")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Open(ctx, plain, "s3cret", nil, 3*time.Second, "komando-test"); code(err) != "QUEUE_CONNECT" {
		t.Errorf("without the CA: %v", err)
	}
	q := open(t, "kafka://app@"+addr+"?tls=true&ca=secret:kafka-ca&sasl=plain", "s3cret", nil)
	if inf, err := q.Info(ctx); err != nil || len(inf.Brokers) != 1 {
		t.Fatalf("with ?ca=: %+v %v", inf, err)
	}
}
