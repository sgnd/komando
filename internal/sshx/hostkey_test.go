package sshx

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A key pinned on first use is shown to the person with its fingerprint,
// and handed to HostKeyPinned (output, audit log); a known key, or a
// changed one, is not announced again.
func TestFirstUsePinIsAnnounced(t *testing.T) {
	dialHome(t)
	var note bytes.Buffer
	var got []NewHostKey
	oldNote, oldHook := hostKeyNote, HostKeyPinned
	hostKeyNote, HostKeyPinned = &note, func(k NewHostKey) { got = append(got, k) }
	t.Cleanup(func() { hostKeyNote, HostKeyPinned = oldNote, oldHook })
	key := newSigner(t).PublicKey()
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 22}
	cb, err := hostKeyCallback("web1", "accept-new")
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("10.0.0.5:22", addr, key); err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(key)
	if len(got) != 1 || got[0] != (NewHostKey{Host: "web1", Address: "10.0.0.5:22", Type: key.Type(), Fingerprint: fp}) {
		t.Fatalf("HostKeyPinned got %+v", got)
	}
	if s := note.String(); !strings.Contains(s, "web1") || !strings.Contains(s, fp) || !strings.Contains(s, "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub") {
		t.Errorf("stderr: %q", s)
	}
	note.Reset()
	if err := cb("10.0.0.5:22", addr, key); err != nil || note.Len() != 0 || len(got) != 1 {
		t.Errorf("a known key was announced again: %v %q", err, note.String())
	}
	if err := cb("10.0.0.5:22", addr, newSigner(t).PublicKey()); err == nil || note.Len() != 0 || len(got) != 1 {
		t.Errorf("a changed key: %v %q", err, note.String())
	}
	strict, _ := hostKeyCallback("web2", "strict")
	if err := strict("10.0.0.6:22", addr, key); err == nil || len(got) != 1 {
		t.Errorf("strict pinned a new key: %v", err)
	}
}
