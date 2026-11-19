package sshx

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/store"
)

// hostCert makes a host certificate for key, signed by ca, for principals.
func hostCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, typ uint32, after, before time.Time, principals ...string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{Key: key, CertType: typ, KeyId: "web", ValidPrincipals: principals,
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix())}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

// noPrincipalCert signs a host certificate with no principals by hand:
// x/crypto's SignCert refuses one, but OpenSSH's ssh-keygen without -n
// makes one, and old x/crypto took it as valid for every name.
func noPrincipalCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, after, before time.Time) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{Key: key, CertType: ssh.HostCert, KeyId: "web", Nonce: make([]byte, 32),
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix()), SignatureKey: ca.PublicKey(), Signature: &ssh.Signature{}}
	if _, err := rand.Read(c.Nonce); err != nil {
		t.Fatal(err)
	}
	m := c.Marshal()
	// the signed part is everything before the signature: a length-prefixed
	// blob of an empty Signature (two empty strings: 8 bytes, 4 for its length)
	sig, err := ca.Sign(rand.Reader, m[:len(m)-12])
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	pk, err := ssh.ParsePublicKey(c.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return pk.(*ssh.Certificate)
}

func trustCA(t *testing.T, name string, ca ssh.Signer, hosts ...string) {
	t.Helper()
	if err := AddHostCA(context.Background(), HostCA{Name: name, Key: pinLine(ca.PublicKey()), Hosts: hosts, AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCAPattern(t *testing.T) {
	for p, ok := range map[string]bool{
		"*.corp.example": true, "web*.corp.example": true, "10.1.2.*": true, "web1.corp.example": true, "WEB.Corp.Example": true,
		"*.corp.co.uk": true, "web*.corp.com.au": true,
		"*": false, "*.*": false, "*.com": false, "*.co.uk": false, "*.com.au": false, "web*.co.uk": false, "*.github.io": false, "?.?": false, "": false, "web[1].corp.example": false, "*.*.*": false,
	} {
		if _, err := CheckCAPattern(p); (err == nil) != ok {
			t.Errorf("%q: %v", p, err)
		}
	}
}

// A certificate from a trusted CA for the dialled name is trusted with no
// pin, also with strict host keys; every other certificate is not.
func TestHostCertTrustedThroughCA(t *testing.T) {
	pinHome(t)
	ca, other, hk := newSigner(t), newSigner(t), newSigner(t).PublicKey()
	trustCA(t, "corp", ca, "*.corp.example")
	now := time.Now()
	day := 24 * time.Hour
	h := &store.Host{Name: "web1", Address: "web1.corp.example", Port: 22, User: "u"}
	cb, err := hostKeyCallback(context.Background(), h, "strict", nil)
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 22}
	good := hostCert(t, ca, hk, ssh.HostCert, now.Add(-day), now.Add(day), "web1.corp.example")
	var heard string
	HostCATrusted = func(_ context.Context, name, ca string) { heard = name + " " + ca }
	t.Cleanup(func() { HostCATrusted = nil })
	if err := cb("web1.corp.example:22", remote, good); err != nil || heard != "web1 corp" {
		t.Fatalf("a good certificate: %v (%q)", err, heard)
	}
	for name, c := range map[string]*ssh.Certificate{
		"another CA":         hostCert(t, other, hk, ssh.HostCert, now.Add(-day), now.Add(day), "web1.corp.example"),
		"another principal":  hostCert(t, ca, hk, ssh.HostCert, now.Add(-day), now.Add(day), "web2.corp.example"),
		"empty principals":   noPrincipalCert(t, ca, hk, now.Add(-day), now.Add(day)),
		"expired":            hostCert(t, ca, hk, ssh.HostCert, now.Add(-2*day), now.Add(-day), "web1.corp.example"),
		"not yet valid":      hostCert(t, ca, hk, ssh.HostCert, now.Add(day), now.Add(2*day), "web1.corp.example"),
		"a user certificate": hostCert(t, ca, hk, ssh.UserCert, now.Add(-day), now.Add(day), "web1.corp.example"),
	} {
		// strict and no pin: the plain key is unknown
		if err := cb("web1.corp.example:22", remote, c); err == nil {
			t.Errorf("%s: trusted", name)
		}
	}
	// a name outside the CA's patterns, with that name in the certificate
	out := hostCert(t, ca, hk, ssh.HostCert, now.Add(-day), now.Add(day), "web1.other.example")
	if err := cb("web1.other.example:22", remote, out); err == nil {
		t.Error("a host outside the CA's patterns was trusted")
	}
	// revoked: the certificate's key, or the CA itself
	if err := RevokeHostKeys([]ssh.PublicKey{hk}); err != nil {
		t.Fatal(err)
	}
	var re *knownhosts.RevokedError
	if err := cb("web1.corp.example:22", remote, good); !errors.As(err, &re) {
		t.Errorf("a revoked host key: %v", err)
	}
	hk2 := newSigner(t).PublicKey()
	good2 := hostCert(t, ca, hk2, ssh.HostCert, now.Add(-day), now.Add(day), "web1.corp.example")
	if err := RevokeHostKeys([]ssh.PublicKey{ca.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	if err := cb("web1.corp.example:22", remote, good2); !errors.As(err, &re) {
		t.Errorf("a revoked CA: %v", err)
	}
}

// An untrusted certificate falls back to its plain key and the pins; a
// login-ask server is never trusted through a CA.
func TestHostCertFallsBackToPins(t *testing.T) {
	pinHome(t)
	ca, hk := newSigner(t), newSigner(t).PublicKey()
	now := time.Now()
	c := hostCert(t, ca, hk, ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour), "web1.corp.example")
	h := &store.Host{Name: "web1", Address: "web1.corp.example", Port: 22, User: "u"}
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 22}
	if _, err := PinHostKey("web1.corp.example:22", hk, false); err != nil {
		t.Fatal(err)
	}
	cb, _ := hostKeyCallback(context.Background(), h, "strict", nil)
	if err := cb("web1.corp.example:22", remote, c); err != nil {
		t.Fatalf("pinned plain key behind an unknown CA: %v", err)
	}
	if pins, _ := PinnedKeys("web1.corp.example:22"); len(pins) != 1 || !SameKey(pins[0], hk) {
		t.Errorf("pins changed: %d", len(pins))
	}
}

// The CA list: add, refuse a second of the same name, list, remove.
func TestHostCAList(t *testing.T) {
	pinHome(t)
	ctx := context.Background()
	ca := newSigner(t)
	trustCA(t, "corp", ca, "*.corp.example")
	if err := AddHostCA(ctx, HostCA{Name: "corp", Key: pinLine(newSigner(t).PublicKey()), Hosts: []string{"*.x.example"}}); !errors.Is(err, ErrHostCAExists) {
		t.Errorf("a second corp: %v", err)
	}
	if c, _ := HostCAFor(ctx, "db.corp.example"); c == nil || c.Name != "corp" {
		t.Errorf("for db: %v", c)
	}
	if c, _ := HostCAFor(ctx, "db.other.example"); c != nil {
		t.Errorf("for another domain: %v", c)
	}
	if err := RemoveHostCA(ctx, "corp"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveHostCA(ctx, "corp"); !errors.Is(err, ErrNoHostCA) {
		t.Errorf("removed twice: %v", err)
	}
	if l, _ := HostCAs(ctx); len(l) != 0 {
		t.Errorf("left: %v", l)
	}
	if err := RevokeHostKeys([]ssh.PublicKey{ca.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	var re *knownhosts.RevokedError
	if err := AddHostCA(ctx, HostCA{Name: "corp", Key: pinLine(ca.PublicKey()), Hosts: []string{"*.corp.example"}}); !errors.As(err, &re) {
		t.Errorf("a revoked CA was added: %v", err)
	}
}

// A real handshake: a server with only a host certificate is reached with
// no pin, because komando asks for certificates first where a CA matches.
func TestDialHostCertificate(t *testing.T) {
	dialHome(t)
	ca, hostKey := newSigner(t), newSigner(t)
	now := time.Now()
	cert := hostCert(t, ca, hostKey.PublicKey(), ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
	cs, err := ssh.NewCertSigner(cert, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	host, port := testSSHD(t, cs)
	trustCA(t, "lab", ca, "127.0.0.1")
	h := &store.Host{Name: "web1", Address: host, Port: port, User: "u", Identity: clientKey(t)}
	c, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 10 * time.Second, HostKeyPolicy: "strict"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if pins, _ := PinnedKeys(net.JoinHostPort(host, itoa(port))); len(pins) != 0 {
		t.Errorf("a CA-trusted host was pinned: %d", len(pins))
	}
}

// A pin always wins: a pinned server is checked against its pin even when
// a trusted CA vouches for the key it shows; CA trust is for unpinned ones.
func TestHostCertPinWins(t *testing.T) {
	now := time.Now()
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 22}
	h := &store.Host{Name: "web1", Address: "web1.corp.example", Port: 22, User: "u"}
	for _, tc := range []struct {
		name     string
		pin      bool
		sameKey  bool
		mismatch bool
	}{
		{name: "pinned, cert over another key", pin: true, mismatch: true},
		{name: "pinned, cert over the pinned key", pin: true, sameKey: true},
		{name: "unpinned, valid CA cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinHome(t)
			ca, pinned, other := newSigner(t), newSigner(t).PublicKey(), newSigner(t).PublicKey()
			trustCA(t, "corp", ca, "*.corp.example")
			if tc.pin {
				if _, err := PinHostKey("web1.corp.example:22", pinned, false); err != nil {
					t.Fatal(err)
				}
			}
			shown := other
			if tc.sameKey {
				shown = pinned
			}
			c := hostCert(t, ca, shown, ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour), "web1.corp.example")
			cb, err := hostKeyCallback(context.Background(), h, "strict", nil)
			if err != nil {
				t.Fatal(err)
			}
			err = cb("web1.corp.example:22", remote, c)
			var hc *hostKeyChanged
			if got := errors.As(err, &hc); got != tc.mismatch {
				t.Fatalf("mismatch %v, want %v (err %v)", got, tc.mismatch, err)
			}
			if !tc.mismatch && err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}

// A jump host in --via is checked as any server: a pin wins over a CA, and
// with no pin a CA certificate is trusted.
func TestHostCertPinWinsVia(t *testing.T) {
	for _, tc := range []struct {
		name string
		pin  bool
		ok   bool
	}{
		{name: "pinned jump host, CA cert over another key", pin: true},
		{name: "unpinned jump host, CA cert", ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialHome(t)
			key := clientKey(t)
			ca, bk := newSigner(t), newSigner(t)
			now := time.Now()
			cert := hostCert(t, ca, bk.PublicKey(), ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour), "127.0.0.1")
			cs, err := ssh.NewCertSigner(cert, bk)
			if err != nil {
				t.Fatal(err)
			}
			bh, bp := testSSHD(t, cs)
			th, tp := testSSHD(t, newSigner(t))
			trustCA(t, "lab", ca, "127.0.0.1")
			if tc.pin {
				if _, err := PinHostKey(net.JoinHostPort(bh, itoa(bp)), newSigner(t).PublicKey(), false); err != nil {
					t.Fatal(err)
				}
			}
			tgt := &store.Host{Name: "target", Address: th, Port: tp, User: "u", Identity: key, Via: "bastion"}
			st := newState(&store.Host{Name: "bastion", Address: bh, Port: bp, User: "u", Identity: key}, tgt)
			c, err := Dial(context.Background(), st, tgt, Options{ConnectTimeout: 10 * time.Second, HostKeyPolicy: "accept-new"})
			if c != nil {
				c.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok %v", err, tc.ok)
			}
			if !tc.ok && !strings.Contains(err.Error(), "HOSTKEY_MISMATCH") && !strings.Contains(err.Error(), "changed") {
				t.Errorf("not a key mismatch: %v", err)
			}
		})
	}
}

// Names match whatever their case and one trailing dot, on the dialled
// name, the CA's pattern and the certificate's principals.
func TestHostCertNamesNormalised(t *testing.T) {
	now := time.Now()
	remote := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 22}
	for _, tc := range []struct{ name, dial, pattern, principal string }{
		{"upper dialled", "WEB1.Corp.Example", "*.corp.example", "web1.corp.example"},
		{"dot dialled", "web1.corp.example.", "*.corp.example", "web1.corp.example"},
		{"upper principal", "web1.corp.example", "*.corp.example", "WEB1.CORP.EXAMPLE"},
		{"dot principal", "web1.corp.example", "*.corp.example", "web1.corp.example."},
		{"dot pattern", "web1.corp.example", "*.corp.example.", "web1.corp.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinHome(t)
			ca, hk := newSigner(t), newSigner(t).PublicKey()
			if err := AddHostCA(context.Background(), HostCA{Name: "corp", Key: pinLine(ca.PublicKey()), Hosts: []string{tc.pattern}, AddedAt: now}); err != nil {
				t.Fatal(err)
			}
			h := &store.Host{Name: "web1", Address: tc.dial, Port: 22, User: "u"}
			cb, err := hostKeyCallback(context.Background(), h, "strict", nil)
			if err != nil {
				t.Fatal(err)
			}
			c := hostCert(t, ca, hk, ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour), tc.principal)
			if err := cb(net.JoinHostPort(tc.dial, "22"), remote, c); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}
}
