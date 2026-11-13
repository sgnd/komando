package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SQL Server makes self-signed certificates whose serial number can be
// negative, which Go refuses to parse since 1.23. komando accepts them
// (the //go:debug line in main.go): a leniency in the format only. The
// chain and the host name are still checked.
func TestNegativeSerialCertificate(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build info")
	}
	found := false
	for _, s := range bi.Settings {
		if s.Key == "DefaultGODEBUG" && strings.Contains(s.Value, "x509negativeserial=1") {
			found = true
		}
	}
	if !found {
		t.Errorf("the build's DefaultGODEBUG has no x509negativeserial=1: %v", bi.Settings)
	}

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sql.example"},
		DNSNames:  []string{"sql.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	neg := withSerial(t, leafDER, big.NewInt(-0x1234567890), caKey)

	leaf, err := x509.ParseCertificate(neg)
	if err != nil {
		t.Fatalf("a certificate with a negative serial does not parse: %v", err)
	}
	if leaf.SerialNumber.Sign() >= 0 {
		t.Fatalf("serial %v, want a negative one", leaf.SerialNumber)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "sql.example"}); err != nil {
		t.Errorf("signed by the trusted CA, for its name: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example"}); err == nil {
		t.Error("another host name was accepted")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: "sql.example"}); err == nil {
		t.Error("a certificate from a CA nobody trusts was accepted")
	}

	// without the setting Go refuses it: this test checks the setting
	t.Setenv("GODEBUG", "x509negativeserial=0")
	if _, err := x509.ParseCertificate(neg); err == nil || !strings.Contains(err.Error(), "negative serial") {
		t.Errorf("with x509negativeserial=0: %v, want the negative serial refused", err)
	}
}

// withSerial is der with its serial number replaced by serial, signed
// again by key (x509.CreateCertificate refuses a negative serial).
func withSerial(t *testing.T, der []byte, serial *big.Int, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	in := cryptobyte.String(der)
	var cert, tbs cryptobyte.String
	var version, oldSerial, sigAlg cryptobyte.String
	var hasVersion bool
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!tbs.ReadOptionalASN1(&version, &hasVersion, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1Element(&oldSerial, cbasn1.INTEGER) || !cert.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) {
		t.Fatal("cannot read the certificate")
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if hasVersion {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(version) })
		}
		b.AddASN1BigInt(serial)
		b.AddBytes(tbs) // the rest of the TBS as it was
	})
	newTBS, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(newTBS)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	var out cryptobyte.Builder
	out.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(sig)
	})
	res, err := out.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return res
}
