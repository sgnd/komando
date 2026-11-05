package openvpn

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// The checks on the server's certificate that a profile asks for:
// remote-cert-tls, ns-cert-type, remote-cert-eku, remote-cert-ku and the
// subject form of verify-x509-name.

// checkUsage checks the certificate's key usages against the profile.
func (c *Config) checkUsage(leaf *x509.Certificate) error {
	// Go treats a certificate without extended key usages as good for
	// anything; OpenVPN wants serverAuth written in it
	if c.RemoteCertTLS && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("the server's certificate is not marked for a TLS server (no serverAuth extended key usage; remote-cert-tls server)")
	}
	if c.NSCertServer && !nsServer(leaf) {
		return errors.New("the server's certificate is not marked for an SSL server (ns-cert-type server)")
	}
	if c.RemoteCertEKU != "" {
		want := ekuOID(c.RemoteCertEKU)
		if !slices.Contains(leafEKUs(leaf), want) {
			return fmt.Errorf("the server's certificate does not have extended key usage %s (remote-cert-eku)", c.RemoteCertEKU)
		}
	}
	if c.RemoteCertKU != nil {
		ku := opensslKU(leaf.KeyUsage)
		ok := ku != 0 && len(c.RemoteCertKU) == 0
		for _, want := range c.RemoteCertKU {
			ok = ok || ku&want == want
		}
		if !ok {
			return fmt.Errorf("the server's certificate has key usage %04x, not what remote-cert-ku asks for", ku)
		}
	}
	return nil
}

// nsServer reports whether the Netscape cert type extension says SSL server.
func nsServer(leaf *x509.Certificate) bool {
	oid := asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oid) {
			var bits asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &bits); err != nil {
				return false
			}
			return bits.At(1) == 1 // bit 0 is SSL client, bit 1 SSL server
		}
	}
	return false
}

// opensslKU is Go's key usage in OpenSSL's bit order, the one
// remote-cert-ku values are written in (digitalSignature 80, ...).
func opensslKU(k x509.KeyUsage) uint16 {
	var ku uint16
	for i := 0; i < 8; i++ {
		if k&(1<<i) != 0 {
			ku |= 0x80 >> i
		}
	}
	if k&x509.KeyUsageDecipherOnly != 0 {
		ku |= 0x8000
	}
	return ku
}

// ekuNames are the extended key usages remote-cert-eku may name (OpenSSL's
// short and long names); any other usage is given as a dotted OID.
var ekuNames = map[string]string{
	"serverauth": "1.3.6.1.5.5.7.3.1", "tls web server authentication": "1.3.6.1.5.5.7.3.1",
	"clientauth": "1.3.6.1.5.5.7.3.2", "tls web client authentication": "1.3.6.1.5.5.7.3.2",
	"codesigning": "1.3.6.1.5.5.7.3.3", "code signing": "1.3.6.1.5.5.7.3.3",
	"emailprotection": "1.3.6.1.5.5.7.3.4", "e-mail protection": "1.3.6.1.5.5.7.3.4",
	"ipsecendsystem": "1.3.6.1.5.5.7.3.5", "ipsec end system": "1.3.6.1.5.5.7.3.5",
	"ipsectunnel": "1.3.6.1.5.5.7.3.6", "ipsec tunnel": "1.3.6.1.5.5.7.3.6",
	"ipsecuser": "1.3.6.1.5.5.7.3.7", "ipsec user": "1.3.6.1.5.5.7.3.7",
	"timestamping": "1.3.6.1.5.5.7.3.8", "time stamping": "1.3.6.1.5.5.7.3.8",
	"ocspsigning": "1.3.6.1.5.5.7.3.9", "ocsp signing": "1.3.6.1.5.5.7.3.9",
}

// ekuOID is the dotted OID for a remote-cert-eku value, "" if it is none.
func ekuOID(s string) string {
	if o, ok := ekuNames[strings.ToLower(s)]; ok {
		return o
	}
	for _, p := range strings.Split(s, ".") {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	if !strings.Contains(s, ".") {
		return ""
	}
	return s
}

var goEKUs = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth: "1.3.6.1.5.5.7.3.1", x509.ExtKeyUsageClientAuth: "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning: "1.3.6.1.5.5.7.3.3", x509.ExtKeyUsageEmailProtection: "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem: "1.3.6.1.5.5.7.3.5", x509.ExtKeyUsageIPSECTunnel: "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser: "1.3.6.1.5.5.7.3.7", x509.ExtKeyUsageTimeStamping: "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning: "1.3.6.1.5.5.7.3.9", x509.ExtKeyUsageAny: "2.5.29.37.0",
}

// leafEKUs are the certificate's extended key usages as dotted OIDs.
func leafEKUs(leaf *x509.Certificate) []string {
	var out []string
	for _, u := range leaf.ExtKeyUsage {
		if o, ok := goEKUs[u]; ok {
			out = append(out, o)
		}
	}
	for _, o := range leaf.UnknownExtKeyUsage {
		out = append(out, o.String())
	}
	return out
}

var dnNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
	"2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title", "2.5.4.17": "postalCode",
	"2.5.4.42": "GN", "2.5.4.43": "initials", "2.5.4.46": "dnQualifier", "1.2.840.113549.1.9.1": "emailAddress",
	"0.9.2342.19200300.100.1.1": "UID", "0.9.2342.19200300.100.1.25": "DC",
}

// subjectDN is the certificate's subject the way OpenVPN prints it for
// verify-x509-name: in certificate order, "C=US, O=Corp, CN=vpn".
func subjectDN(leaf *x509.Certificate) string {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(leaf.RawSubject, &seq); err != nil || len(rest) > 0 {
		return ""
	}
	parts := make([]string, 0, len(seq))
	for _, rdn := range seq {
		vs := make([]string, 0, len(rdn))
		for _, a := range rdn {
			name, ok := dnNames[a.Type.String()]
			if !ok {
				name = a.Type.String()
			}
			vs = append(vs, name+"="+fmt.Sprint(a.Value))
		}
		parts = append(parts, strings.Join(vs, " + "))
	}
	return strings.Join(parts, ", ")
}

// dnAttr is one attribute of a subject: its type as a dotted OID and its
// value.
type dnAttr struct{ typ, val string }

// matchSubject reports whether the certificate's subject is exactly the
// pinned one, attribute by attribute: "C=US, O=Corp, CN=x" (OpenVPN's
// form) or the old "/C=US/O=Corp/CN=x". The subject is compared as a
// structure, never as printed text, so a value that holds ", CN=x" or
// extra spaces cannot pose as more attributes.
func matchSubject(leaf *x509.Certificate, pin string) bool {
	want, ok := parsePin(pin)
	if !ok {
		return false
	}
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(leaf.RawSubject, &seq); err != nil || len(rest) > 0 || len(seq) != len(want) {
		return false
	}
	for i, rdn := range seq {
		if len(rdn) != len(want[i]) {
			return false
		}
		for j, a := range rdn {
			v, ok := a.Value.(string)
			if !ok || a.Type.String() != want[i][j].typ || v != want[i][j].val {
				return false
			}
		}
	}
	return true
}

// parsePin splits a pinned subject into its RDNs ("+" joins the
// attributes of one). Spaces around separators are allowed; a part
// without "=" or with an unknown type makes the pin match nothing.
func parsePin(s string) ([][]dnAttr, bool) {
	s = strings.TrimSpace(s)
	sep := ","
	if strings.HasPrefix(s, "/") {
		sep, s = "/", s[1:]
	}
	if s == "" {
		return nil, false
	}
	var out [][]dnAttr
	for _, p := range strings.Split(s, sep) {
		var rdn []dnAttr
		for _, a := range strings.Split(p, "+") {
			k, v, ok := strings.Cut(a, "=")
			typ := dnOID(strings.TrimSpace(k))
			if !ok || typ == "" {
				return nil, false
			}
			rdn = append(rdn, dnAttr{typ, strings.TrimSpace(v)})
		}
		out = append(out, rdn)
	}
	return out, true
}

// dnOID is the dotted OID for an attribute type a pin names: a short name
// such as CN (any case) or the OID itself; "" if it is neither.
func dnOID(k string) string {
	for oid, name := range dnNames {
		if strings.EqualFold(k, name) {
			return oid
		}
	}
	if !strings.Contains(k, ".") {
		return ""
	}
	for _, p := range strings.Split(k, ".") {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return ""
		}
	}
	return k
}
