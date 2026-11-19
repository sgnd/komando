package sshx

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
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

func trustCA(t *testing.T, name string, ca ssh.Signer, hosts ...string) {
	t.Helper()
	if err := AddHostCA(context.Background(), HostCA{Name: name, Key: pinLine(ca.PublicKey()), Hosts: hosts, AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCAPattern(t *testing.T) {
	for p, ok := range map[string]bool{
		"*.corp.example": true, "web*.corp.example": true, "10.1.2.*": true, "web1.corp.example": true, "WEB.Corp.Example": true,
		"*": false, "*.*": false, "*.com": false, "?.?": false, "": false, "web[1].corp.example": false, "*.*.*": false,
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
