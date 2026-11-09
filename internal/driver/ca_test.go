package driver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

func TestParseCA(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://app@db.internal:5432/app?ca=secret:rds-ca":            "secret:rds-ca",
		"postgres://app@db.internal/app?sslmode=verify-full&ca=secret:x":  "secret:x",
		"mysql://shop@db.internal/shop?ca=secret:azure-ca":                "secret:azure-ca",
		"mysql://shop@db.internal/shop?tls=true&ca=secret:azure-ca":       "secret:azure-ca",
		"rediss://default@cache.internal:6380/0?ca=secret:elasticache-ca": "secret:elasticache-ca",
		"memcacheds://cache.internal:11211?ca=secret:ca":                  "secret:ca",
		"postgres://app@db.internal/app":                                  "",
	} {
		tg, err := Parse(raw)
		if err != nil || tg.CA != want {
			t.Errorf("%s: CA %q %v, want %q", raw, tg.CA, err, want)
		}
	}
	for _, raw := range []string{
		"postgres://app@db/app?ca=/etc/ssl/ca.pem", // a path, not a secret
		"postgres://app@db/app?ca=secret:",         // no name
		"postgres://app@db/app?sslmode=disable&ca=secret:x",
		"mysql://shop@db/shop?tls=skip-verify&ca=secret:x",
		"redis://cache:6379/0?ca=secret:x", // no TLS
		"memcached://cache:11211?ca=secret:x",
	} {
		_, err := Parse(raw)
		if oe, ok := err.(*out.Error); !ok || oe.Exit != out.ExitUsage {
			t.Errorf("%s: want a usage error, got %v", raw, err)
		}
	}
}

func TestWithoutCA(t *testing.T) {
	got := WithoutCA("postgres://app@db/app?sslmode=require&ca=secret:x&application_name=a")
	if strings.Contains(got, "ca=") || !strings.Contains(got, "sslmode=require") || !strings.Contains(got, "application_name=a") {
		t.Errorf("WithoutCA: %s", got)
	}
	if s := "postgres://app@db/app?sslmode=require"; WithoutCA(s) != s {
		t.Errorf("a URL without ca= stays as it is")
	}
}

func TestRootCAs(t *testing.T) {
	saved := ResolveSecret
	defer func() { ResolveSecret = saved }()
	tg, _ := Parse("rediss://cache:6380/0?ca=secret:ca")
	ResolveSecret = func(string) (string, error) { return "", ErrSecretNotFound }
	if _, err := tg.RootCAs(); err == nil || err.(*out.Error).Code != "SECRET_NOT_FOUND" {
		t.Errorf("missing secret: %v", err)
	}
	ResolveSecret = func(string) (string, error) { return "not a certificate", nil }
	if _, err := tg.RootCAs(); err == nil || err.(*out.Error).Code != "BAD_CA" {
		t.Errorf("not PEM: %v", err)
	}
	if p, err := (Target{}).RootCAs(); p != nil || err != nil {
		t.Errorf("no ca=: %v %v", p, err)
	}
}

// CAPEM hands a client that reads a file only the certificates a pool
// takes, re-encoded: no text around them, no other blocks, no blank lines
// (the dump tool script ends the CA at an empty line).
func TestCAPEM(t *testing.T) {
	saved := ResolveSecret
	defer func() { ResolveSecret = saved }()
	cert := func(name string) []byte {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	a, b := cert("CA one"), cert("CA two")
	clean := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}))
	stored := "Bundle from the cloud's console\r\n\r\n" +
		strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a})), "\n", "\r\n") +
		"\n# comment\n" + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not for a CA file")})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})) + "\n\n"
	ResolveSecret = func(string) (string, error) { return stored, nil }
	tg, _ := Parse("postgres://app@db.internal/app?ca=secret:pg-ca")
	got, err := tg.CAPEM()
	if err != nil || got != clean {
		t.Fatalf("CAPEM: %v\n%s", err, got)
	}
	if strings.Contains(got, "\n\n") || strings.Contains(got, "\r") {
		t.Errorf("blank line or CR in %q", got)
	}
	if pool, err := tg.RootCAs(); err != nil || pool == nil || !pool.Equal(func() *x509.CertPool {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM([]byte(stored))
		return p
	}()) {
		t.Errorf("RootCAs takes what it took before: %v", err)
	}
	if s, err := (Target{}).CAPEM(); s != "" || err != nil {
		t.Errorf("no ca=: %q %v", s, err)
	}
	ResolveSecret = func(string) (string, error) {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: a})), nil
	}
	if _, err := tg.CAPEM(); err == nil || err.(*out.Error).Code != "BAD_CA" {
		t.Errorf("a key only: %v", err)
	}
}
