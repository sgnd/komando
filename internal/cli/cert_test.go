package cli

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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
	kpem string
}

// makeCert makes a certificate for names (DNS names or IPs), signed by
// parent (nil: a CA that signs itself).
func makeCert(t *testing.T, cn string, names []string, notBefore, notAfter time.Time, parent *testCert) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	signer, signKey := tmpl, key
	if parent == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
	} else {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	return &testCert{cert: c, key: key,
		pem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		kpem: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))}
}

// tlsServer serves leaf (and its chain) on 127.0.0.1.
func tlsServer(t *testing.T, leaf *testCert, chain ...*testCert) string {
	t.Helper()
	certs := [][]byte{leaf.cert.Raw}
	for _, c := range chain {
		certs = append(certs, c.cert.Raw)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: certs, PrivateKey: leaf.key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestParseCertURL(t *testing.T) {
	st := testState()
	st.Conns = map[string]*store.Conn{"shopdb:5432": {Name: "shopdb:5432"}}
	for _, tc := range []struct {
		in, addr, sn string
		ok, err      bool
	}{
		{"https://example.com", "example.com:443", "example.com", true, false},
		{"https://example.com:8443/path?q=1", "example.com:8443", "example.com", true, false},
		{"ldaps://ldap.example.com", "ldap.example.com:636", "ldap.example.com", true, false},
		{"gopher://x.example.com", "", "", false, true},
		{"example.com:443", "example.com:443", "example.com", true, false},
		{"[::1]:8443", "[::1]:8443", "::1", true, false},
		{"deploy@10.0.0.1:22", "", "", false, false}, // an ad-hoc server
		{"web1", "", "", false, false},
		{"@web", "", "", false, false},
		{"shopdb:5432", "", "", false, false}, // a name in the inventory
		{"example.com:http", "", "", false, false},
	} {
		addr, sn, ok, err := parseCertURL(st, tc.in)
		if (err != nil) != tc.err || ok != tc.ok || addr != tc.addr || sn != tc.sn {
			t.Errorf("%s: got %q %q %v %v", tc.in, addr, sn, ok, err)
		}
	}
}

func TestCertFromPEMIgnoresKeys(t *testing.T) {
	now := time.Now()
	ca := makeCert(t, "Test CA", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), nil)
	leaf := makeCert(t, "www.example.com", []string{"www.example.com", "example.com", "10.0.0.5"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), ca)
	ci, ok := certFromPEM(leaf.kpem + leaf.pem + ca.pem)
	if !ok || ci.Subject != "www.example.com" || ci.Chain != 2 || ci.Issuer != "Test Org (Test CA)" {
		t.Fatalf("got %+v", ci)
	}
	if strings.Join(ci.Names, ",") != "www.example.com,example.com,10.0.0.5" {
		t.Errorf("names %v", ci.Names)
	}
	if _, ok := certFromPEM(leaf.kpem); ok {
		t.Error("a key alone is no certificate")
	}
}

// The remote filter prints the certificate blocks of a bundle and never a
// line of its private key.
func TestCertBlocksAwkDropsKeys(t *testing.T) {
	unixOnly(t, "runs a server's awk script")
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	now := time.Now()
	leaf := makeCert(t, "a.example.com", []string{"a.example.com"}, now, now.Add(time.Hour), nil)
	bundle := leaf.pem + leaf.kpem + strings.ReplaceAll(leaf.pem, "\n", "\r\n") +
		"-----BEGIN RSA PRIVATE KEY-----\nSECRETLINE\n-----END RSA PRIVATE KEY-----\n"
	cmd := exec.Command("sh", "-c", certBlocksAwk)
	cmd.Stdin = strings.NewReader(bundle)
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "PRIVATE") || strings.Contains(got, "SECRETLINE") {
		t.Fatalf("a key line came through:\n%s", got)
	}
	keyBody := strings.Split(leaf.kpem, "\n")[1]
	if strings.Contains(got, keyBody) {
		t.Fatal("the key's base64 came through")
	}
	if ci, ok := certFromPEM(got); !ok || ci.Chain != 2 {
		t.Fatalf("certificates lost: %+v\n%s", ci, got)
	}
}

const certDiscoveryOut = `== root
yes
== certbot
present
== certbot-live
/etc/letsencrypt/live/example.com/cert.pem
== units
Id=certbot.timer
LoadState=loaded
ActiveState=active
Result=success

Id=certbot.service
LoadState=loaded
ActiveState=failed
Result=exit-code

Id=snap.certbot.renew.timer
LoadState=not-found
ActiveState=inactive
Result=success

== cron
== nginx
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
	ssl_certificate "/etc/ssl/certs/shop.pem";
    ssl_certificate /etc/nginx/certs/$ssl_server_name.crt;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
== haproxy
    bind *:443 ssl crt /etc/haproxy/certs/ crt /etc/ssl/certs/shop.pem alpn h2
== apache
  SSLCertificateFile /etc/apache2/ssl/site.crt
`

func TestParseCertDiscovery(t *testing.T) {
	d := parseCertDiscovery(certDiscoveryOut)
	want := []string{
		"/etc/letsencrypt/live/example.com/cert.pem",
		"/etc/letsencrypt/live/example.com/fullchain.pem",
		"/etc/ssl/certs/shop.pem",
		"/etc/haproxy/certs/",
		"/etc/apache2/ssl/site.crt",
	}
	if strings.Join(d.paths, "|") != strings.Join(want, "|") {
		t.Fatalf("paths %q", d.paths)
	}
	for _, p := range d.paths {
		if strings.Contains(p, "privkey") || strings.Contains(p, "$") {
			t.Errorf("%s must not be read", p)
		}
	}
	if s := d.sources["/etc/ssl/certs/shop.pem"]; strings.Join(s, ",") != "nginx,haproxy" {
		t.Errorf("sources %v", s)
	}
	if d.sources["/etc/letsencrypt/live/example.com/cert.pem"][0] != "certbot example.com" {
		t.Errorf("certbot source %v", d.sources)
	}
	if d.certbot == nil || len(d.certbot.Renewal) != 2 || !strings.Contains(d.certbot.Problem, "certbot.service failed") {
		t.Fatalf("certbot %+v", d.certbot)
	}
	// no certbot, no root: nothing about certbot
	d = parseCertDiscovery("== root\nno\n== certbot\n== nginx\n")
	if d.certbot != nil || len(d.paths) != 0 {
		t.Errorf("got %+v", d)
	}
	// certbot without root and without a timer
	d = parseCertDiscovery("== root\nno\n== certbot\npresent\n== units\n")
	if d.certbot == nil || d.certbot.Problem != "" || len(d.notes) != 2 {
		t.Errorf("got %+v %v", d.certbot, d.notes)
	}
}

func TestParseCertFiles(t *testing.T) {
	now := time.Now()
	a := makeCert(t, "a.example.com", []string{"a.example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour), nil)
	b := makeCert(t, "b.example.com", []string{"b.example.com"}, now.Add(-time.Hour), now.Add(5*24*time.Hour), nil)
	s := "== path /etc/a.pem\n== file /etc/a.pem\n" + a.pem +
		"== path /etc/missing.pem\n" +
		"== path /etc/haproxy/certs/\n== file /etc/haproxy/certs/b.pem\n" + b.pem + "== file /etc/haproxy/certs/b.key\n" +
		"== path /etc/empty.pem\n== file /etc/empty.pem\n"
	res := parseCertFiles(s, map[string][]string{"/etc/a.pem": {"nginx"}})
	if len(res) != 4 {
		t.Fatalf("got %d: %+v", len(res), res)
	}
	if res[0].Subject != "a.example.com" || res[0].Sources[0] != "nginx" {
		t.Errorf("a: %+v", res[0])
	}
	if res[1].Status != "unreadable" || res[1].Path != "/etc/missing.pem" {
		t.Errorf("missing: %+v", res[1])
	}
	if res[2].Path != "/etc/haproxy/certs/b.pem" || res[2].Subject != "b.example.com" {
		t.Errorf("b: %+v", res[2])
	}
	if res[3].Status != "no_certificate" {
		t.Errorf("empty: %+v", res[3])
	}
	rateCert(&res[0], 30*24*time.Hour)
	rateCert(&res[1], 30*24*time.Hour)
	rateCert(&res[2], 30*24*time.Hour)
	if res[0].Status != "ok" || res[0].DaysLeft < 58 || res[1].Status != "unreadable" || res[2].Status != "expiring" || res[2].DaysLeft != 4 {
		t.Errorf("rated: %+v / %+v / %+v", res[0], res[1], res[2])
	}
}

func TestRateCert(t *testing.T) {
	now := time.Now()
	no := false
	for _, tc := range []struct {
		c    certInfo
		want string
	}{
		{certInfo{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(-time.Minute)}, "expired"},
		{certInfo{NotBefore: now.Add(time.Hour), NotAfter: now.Add(100 * 24 * time.Hour)}, "not_yet_valid"},
		{certInfo{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(100 * 24 * time.Hour), Verified: &no, VerifyError: "x509: unknown authority"}, "not_trusted"},
		{certInfo{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(29 * 24 * time.Hour)}, "expiring"},
		{certInfo{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(31 * 24 * time.Hour)}, "ok"},
	} {
		rateCert(&tc.c, 30*24*time.Hour)
		if tc.c.Status != tc.want {
			t.Errorf("got %s, want %s (%+v)", tc.c.Status, tc.want, tc.c)
		}
	}
}

func TestServedCert(t *testing.T) {
	now := time.Now()
	ca := makeCert(t, "Test CA", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), nil)
	leaf := makeCert(t, "localhost", []string{"localhost", "127.0.0.1"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), ca)
	addr := tlsServer(t, leaf, ca)
	d := &net.Dialer{}

	ci, err := servedCert(context.Background(), d.DialContext, addr, "127.0.0.1", 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if ci.Verified == nil || *ci.Verified || ci.Chain != 2 || ci.Subject != "localhost" {
		t.Errorf("system roots must not trust the test CA: %+v", ci)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	certRoots = pool
	defer func() { certRoots = nil }()
	if ci, err = servedCert(context.Background(), d.DialContext, addr, "127.0.0.1", 5*time.Second, ""); err != nil || !*ci.Verified {
		t.Errorf("trusted: %+v %v", ci, err)
	}
	if ci, _ = servedCert(context.Background(), d.DialContext, addr, "other.example.com", 5*time.Second, ""); *ci.Verified {
		t.Errorf("a wrong name must not verify: %+v", ci)
	}

	// not TLS
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("HTTP/1.0 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	if _, err := servedCert(context.Background(), d.DialContext, ln.Addr().String(), "x", 5*time.Second, ""); toErr(err).Code != "TLS_HANDSHAKE_FAILED" {
		t.Errorf("plain text: %v", err)
	}
	// nothing listens
	if _, err := servedCert(context.Background(), d.DialContext, "127.0.0.1:1", "x", 5*time.Second, ""); toErr(err).Exit != out.ExitConnect {
		t.Errorf("closed port: %v", err)
	}
}

func TestCertCheckURLCommand(t *testing.T) {
	invHome(t)
	now := time.Now()
	ca := makeCert(t, "Test CA", nil, now.Add(-time.Hour), now.Add(365*24*time.Hour), nil)
	good := makeCert(t, "localhost", []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), ca)
	soon := makeCert(t, "localhost", []string{"127.0.0.1"}, now.Add(-time.Hour), now.Add(10*24*time.Hour), ca)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	certRoots = pool
	defer func() { certRoots = nil }()
	a1, a2 := tlsServer(t, good, ca), tlsServer(t, soon, ca)

	d := mustRun(t, "cert", "check", a1)
	r := d["results"].([]any)[0].(map[string]any)
	c := r["certs"].([]any)[0].(map[string]any)
	if r["ok"] != true || c["status"] != "ok" || c["verified"] != true || c["days_left"].(float64) < 88 {
		t.Fatalf("got %v", r)
	}
	e := wantCode(t, "CERT_PROBLEMS", "cert", "check", a1, a2)
	if e.Exit != out.ExitError || !strings.Contains(e.Message, a2) || strings.Contains(e.Message, a1+",") {
		t.Errorf("got %+v", e)
	}
	mustRun(t, "cert", "check", a2, "--warn", "7d")
	wantCode(t, "USAGE", "cert", "check", a1, "--warn", "soon")
	if e := wantCode(t, "CONNECT_FAILED", "cert", "check", "127.0.0.1:1"); e.Exit != out.ExitConnect {
		t.Errorf("exit %d", e.Exit)
	}
	// a dry run connects nowhere
	d = mustRun(t, "cert", "check", "127.0.0.1:1", "--dry-run")
	if d["would_connect"] == nil {
		t.Errorf("dry run: %v", d)
	}
	e = wantCode(t, "TARGET_NOT_FOUND", "cert", "check", "shop.example.com")
	if !strings.Contains(e.Hint, "https://shop.example.com") {
		t.Errorf("hint %q", e.Hint)
	}
}

func TestCertCheckHostCommand(t *testing.T) {
	srv := startFakeServer(t)
	now := time.Now()
	leaf := makeCert(t, "example.com", []string{"example.com", "www.example.com"}, now.Add(-time.Hour), now.Add(80*24*time.Hour), nil)
	// the fake server answers every command alike: the discovery reads its
	// sections, the certificate read its path and file sections
	srv.reply(certDiscoveryOut + "== path /etc/letsencrypt/live/example.com/fullchain.pem\n== file /etc/letsencrypt/live/example.com/fullchain.pem\n" + leaf.pem)
	d, e := invRun(t, "--host-key-policy", "accept-new", "cert", "check", "dev")
	if e == nil || e.Code != "CERT_PROBLEMS" {
		t.Fatalf("certbot's failed renewal is a problem: %+v %v", e, d)
	}
	r := d["results"].([]any)[0].(map[string]any)
	certs := r["certs"].([]any)
	if len(certs) != 1 || certs[0].(map[string]any)["status"] != "ok" {
		t.Fatalf("certs %v", certs)
	}
	if !strings.Contains(r["certbot"].(map[string]any)["problem"].(string), "failed") {
		t.Errorf("certbot %v", r["certbot"])
	}
	execs := srv.take()
	if len(execs) != 2 {
		t.Fatalf("want discovery and read, got %d", len(execs))
	}
	for _, x := range execs {
		if strings.Contains(x.cmd, "privkey") || strings.Contains(x.cmd, "sudo -S") {
			t.Errorf("command reads a key or asks for a password: %s", x.cmd)
		}
	}
	if !strings.Contains(execs[1].cmd, "BEGIN CERTIFICATE") {
		t.Errorf("the read must filter certificate blocks: %s", execs[1].cmd)
	}
}
