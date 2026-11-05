package openvpn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testPKI is a CA that signs the certificates the tests need.
type testPKI struct {
	t      *testing.T
	ca     *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
	serial int64
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &testPKI{t: t, ca: ca, caKey: k, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 1}
}

// issue signs a leaf; tpl gives the subject and usages.
func (p *testPKI) issue(tpl *x509.Certificate) tls.Certificate {
	p.t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.serial++
	tpl.SerialNumber = big.NewInt(p.serial)
	tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		p.t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func (p *testPKI) server() tls.Certificate {
	return p.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "server"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature})
}

// verify runs the client's check of the server certificate.
func verify(t *testing.T, cfg *Config, crt tls.Certificate) error {
	t.Helper()
	tc, err := (&Client{cfg: cfg}).tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	return tc.VerifyPeerCertificate(crt.Certificate, nil)
}

// verify-x509-name with the subject type compares the whole subject: a
// certificate from the same CA with a shorter, empty or equal CN but other
// O or C must not pass
func TestVerifyX509Name(t *testing.T) {
	p := newPKI(t)
	subj := func(c, o, cn string) *x509.Certificate {
		n := pkix.Name{CommonName: cn}
		if c != "" {
			n.Country = []string{c}
		}
		if o != "" {
			n.Organization = []string{o}
		}
		return &x509.Certificate{Subject: n, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	}
	legit := p.issue(subj("US", "Corp", "vpn.corp.com"))
	for _, c := range []struct {
		name, typ string
		crt       tls.Certificate
		ok        bool
	}{
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", legit, true},
		{"C=US,O=Corp,CN=vpn.corp.com", "subject", legit, true},
		{"/C=US/O=Corp/CN=vpn.corp.com", "subject", legit, true},
		{"CN=vpn.corp.com,O=Corp,C=US", "subject", legit, true}, // Go's own form, exact
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", p.issue(subj("", "", "vpn")), false},
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", p.issue(subj("", "", "vpn.corp")), false},
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", p.issue(subj("", "Other", "")), false},
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", p.issue(subj("XX", "Attacker", "vpn.corp.com")), false},
		{"C=US, O=Corp, CN=vpn.corp.com", "subject", p.issue(subj("", "", "other.corp.com")), false},
		{"CN=vpn.corp.com", "subject", legit, false}, // the whole subject, as OpenVPN does
		{"CN=vpn.corp.com", "subject", p.issue(subj("", "", "vpn.corp.com")), true},
		{"CN=vpn.corp.com", "subject", p.issue(subj("", "", "")), false},
		// a crafted value must not pose as more attributes, and spaces in a
		// certificate value are never trimmed
		{"C=US, O=Corp, CN=vpn", "subject", p.issue(subj("US, O=Corp, CN=vpn", "", "")), false},
		{"/C=US/O=Corp/CN=vpn", "subject", p.issue(subj("US, O=Corp, CN=vpn", "", "")), false},
		{"C=US, O=Corp, CN=vpn", "subject", p.issue(subj("US", "Corp,  CN=vpn", "")), false},
		{"C=US, O=Corp, CN=vpn", "subject", p.issue(subj("US", "Corp", "vpn ")), false},
		{"C=US, O=Corp, CN=vpn", "subject", p.issue(subj("US", "Corp", "vpn")), true},
		{"C=US, O=Corp + CN=vpn", "subject", p.issue(subj("US", "Corp", "vpn")), false}, // other RDN grouping
		{"c=US,o=Corp,cn=vpn", "subject", p.issue(subj("US", "Corp", "vpn")), true},
		{"2.5.4.6=US, 2.5.4.10=Corp, 2.5.4.3=vpn", "subject", p.issue(subj("US", "Corp", "vpn")), true},
		{"C=US, O=Corp, CN=vpn,", "subject", p.issue(subj("US", "Corp", "vpn")), false},
		{"C=US, Bogus=Corp, CN=vpn", "subject", p.issue(subj("US", "Corp", "vpn")), false},
		{"vpn.corp.com", "name", legit, true},
		{"vpn.corp.com", "name", p.issue(subj("", "", "vpn")), false},
		{"vpn.corp", "name-prefix", legit, true},
		{"vpn.corp", "name-prefix", p.issue(subj("", "", "vpn")), false},
	} {
		cfg := &Config{CA: p.caPEM, VerifyName: c.name, VerifyNameType: c.typ}
		if err := verify(t, cfg, c.crt); (err == nil) != c.ok {
			leaf, _ := x509.ParseCertificate(c.crt.Certificate[0])
			t.Errorf("%s %q vs %q: %v, want ok=%v", c.typ, c.name, subjectDN(leaf), err, c.ok)
		}
	}
}

func TestSubjectDN(t *testing.T) {
	p := newPKI(t)
	crt := p.issue(&x509.Certificate{Subject: pkix.Name{Country: []string{"US"}, Province: []string{"CA"}, Organization: []string{"Corp"},
		OrganizationalUnit: []string{"IT"}, CommonName: "vpn"}})
	leaf, _ := x509.ParseCertificate(crt.Certificate[0])
	if got := subjectDN(leaf); got != "C=US, ST=CA, O=Corp, OU=IT, CN=vpn" {
		t.Errorf("subjectDN = %q", got)
	}
}

// ns-cert-type, remote-cert-eku and remote-cert-ku are checked, never
// ignored: another user's client certificate from the same CA must not
// pass as the server
func TestServerCertUsage(t *testing.T) {
	p := newPKI(t)
	nsType := func(bit int) pkix.Extension {
		b := asn1.BitString{Bytes: []byte{byte(0x80 >> bit)}, BitLength: bit + 1}
		v, _ := asn1.Marshal(b)
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}, Value: v}
	}
	server := p.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "server"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtraExtensions: []pkix.Extension{nsType(1)}})
	client := p.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{nsType(0)}})
	ipsec := p.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "gw"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}})
	noEKU := p.issue(&x509.Certificate{Subject: pkix.Name{CommonName: "bare"}})
	profile := "client\nremote vpn.example.com 1194\nauth-user-pass\n<ca>\n" + string(p.caPEM) + "</ca>\n"
	for _, c := range []struct {
		line  string
		crt   tls.Certificate
		label string
		ok    bool
	}{
		{"remote-cert-tls server", server, "server", true},
		{"remote-cert-tls server", client, "client", false},
		{"remote-cert-tls server", noEKU, "no EKU", false},
		{"ns-cert-type server", server, "server", true},
		{"ns-cert-type server", client, "client", false},
		{"ns-cert-type server", noEKU, "no EKU", false},
		{"remote-cert-eku \"TLS Web Server Authentication\"", server, "server", true},
		{"remote-cert-eku serverAuth", client, "client", false},
		{"remote-cert-eku 1.3.6.1.5.5.7.3.1", server, "server", true},
		{"remote-cert-eku 1.3.6.1.5.5.7.3.1", noEKU, "no EKU", false},
		{"remote-cert-ku a0", server, "server", true},
		{"remote-cert-ku 0xa0", server, "server", true},
		{"remote-cert-ku 0XA0", client, "client", false},
		{"remote-cert-eku \"IPSec End System\"", server, "server", false},
		{"remote-cert-eku \"IPSec End System\"", ipsec, "IPsec", true},
		{"remote-cert-eku ipsecEndSystem", ipsec, "IPsec", true},
		{"remote-cert-eku ipsecTunnel", ipsec, "IPsec", false},
		{"remote-cert-ku a0", client, "client", false},
		{"remote-cert-ku 80 a0", client, "client", true},
		{"remote-cert-ku", noEKU, "no KU", false},
		{"remote-cert-ku", client, "client", true},
	} {
		cfg, err := Parse(profile + c.line + "\n")
		if err != nil {
			t.Fatalf("%s: %v", c.line, err)
		}
		if err := verify(t, cfg, c.crt); (err == nil) != c.ok {
			t.Errorf("%s with the %s certificate: %v, want ok=%v", c.line, c.label, err, c.ok)
		}
	}
	for _, bad := range []struct{ line, want string }{
		{"ns-cert-type client", "only server"},
		{"remote-cert-eku nonsense", "remote-cert-eku"},
		{"remote-cert-eku", "remote-cert-eku"},
		{"remote-cert-ku zz", "hex"},
		{"remote-cert-ku 0x", "hex"},
		{"remote-cert-ku 0x0", "hex"},
	} {
		if _, err := Parse(profile + bad.line + "\n"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q: %v, want %q", bad.line, err, bad.want)
		}
	}
}
