package sshx

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// signCert makes a user certificate for pub, signed by ca.
func signCert(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, typ uint32, after, before time.Time) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{Key: pub, CertType: typ, KeyId: "test", ValidPrincipals: []string{"deploy"},
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{}}}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func writeCert(t *testing.T, c *ssh.Certificate) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id-cert.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(c), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// certServer is a loopback SSH server that lets in only users whose
// certificate ca signed; it returns a function that tries one login.
func certServer(t *testing.T, ca ssh.Signer) func(signers ...ssh.Signer) error {
	t.Helper()
	checker := &ssh.CertChecker{IsUserAuthority: func(auth ssh.PublicKey) bool { return SameKey(auth, ca.PublicKey()) }}
	cfg := &ssh.ServerConfig{PublicKeyCallback: checker.Authenticate}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if sc, _, _, err := ssh.NewServerConn(nc, cfg); err == nil {
					sc.Close()
				}
				nc.Close()
			}()
		}
	}()
	return func(signers ...ssh.Signer) error {
		c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
		if err == nil {
			c.Close()
		}
		return err
	}
}

// A key with its user certificate logs in to a server that trusts only
// the certificate authority, not the key itself.
func TestUserCertLogsIn(t *testing.T) {
	ca, key := newSigner(t), newSigner(t)
	now := time.Now()
	good := writeCert(t, signCert(t, ca, key.PublicKey(), ssh.UserCert, now.Add(-time.Hour), now.Add(time.Hour)))
	signers := CertSigners(key, good)
	if len(signers) != 2 {
		t.Fatalf("signers %d, want the certificate and the key", len(signers))
	}
	login := certServer(t, ca)
	if err := login(signers...); err != nil {
		t.Fatalf("login with the certificate: %v", err)
	}
	// without the certificate the same key is refused there
	if err := login(key); err == nil {
		t.Fatal("the bare key was let in: the test server does not check certificates")
	}
}

// A certificate that is out of date, for another key, a host certificate
// or missing is left out: the key alone is offered.
func TestCertSignersLeaveOutBadOnes(t *testing.T) {
	ca, key, other := newSigner(t), newSigner(t), newSigner(t)
	now := time.Now()
	for name, p := range map[string]string{
		"expired":     writeCert(t, signCert(t, ca, key.PublicKey(), ssh.UserCert, now.Add(-2*time.Hour), now.Add(-time.Hour))),
		"not yet":     writeCert(t, signCert(t, ca, key.PublicKey(), ssh.UserCert, now.Add(time.Hour), now.Add(2*time.Hour))),
		"another key": writeCert(t, signCert(t, ca, other.PublicKey(), ssh.UserCert, now.Add(-time.Hour), now.Add(time.Hour))),
		"host cert":   writeCert(t, signCert(t, ca, key.PublicKey(), ssh.HostCert, now.Add(-time.Hour), now.Add(time.Hour))),
		"missing":     filepath.Join(t.TempDir(), "none-cert.pub"),
	} {
		if got := CertSigners(key, p); len(got) != 1 || got[0] != key {
			t.Errorf("%s: %d signers", name, len(got))
		}
	}
	if certPathFor("sealed:abc", nil) != "" || certPathFor("/k/id", nil) != "/k/id-cert.pub" {
		t.Error("certPathFor")
	}
}
