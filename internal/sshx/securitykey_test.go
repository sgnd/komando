package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/store"
)

// skKeyFile writes a FIDO2 key file as ssh-keygen -t ed25519-sk does (the
// key handle in OpenSSH's format, which Go cannot sign with) and its .pub.
func skKeyFile(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubBlob := ssh.Marshal(struct {
		Type, Key, App string
	}{"sk-ssh-ed25519@openssh.com", string(pubKey), "ssh:"})
	pub, err := ssh.ParsePublicKey(pubBlob)
	if err != nil {
		t.Fatal(err)
	}
	priv := ssh.Marshal(struct {
		Check1, Check2 uint32
		Keytype        string
		Rest           []byte `ssh:"rest"`
	}{7, 7, "sk-ssh-ed25519@openssh.com", ssh.Marshal(struct {
		Pub, App string
		Flags    uint8
		Handle   string
		Reserved string
		Comment  string
	}{string(pubKey), "ssh:", 1, "handle", "", "me@laptop"})})
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	body := append([]byte("openssh-key-v1\x00"), ssh.Marshal(struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}{"none", "none", "", 1, pubBlob, priv})...)
	p := filepath.Join(t.TempDir(), "id_ed25519_sk")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body})); err == nil {
		t.Fatal("Go parsed a security key file; the test file is wrong")
	}
	return p, pub
}

// A security key (FIDO2) as a server's --identity: komando looks for it in
// ssh-agent by its public key, and without an agent says to ssh-add it,
// never that its file is broken.
func TestSecurityKeyGoesThroughTheAgent(t *testing.T) {
	dialHome(t)
	p, pub := skKeyFile(t)
	if !IsSecurityKey(pub) {
		t.Fatal("IsSecurityKey")
	}
	h := &store.Host{Name: "web1", Address: "10.0.0.5", User: "u", Identity: p}
	_, _, err := authMethods(newState(h), h, 0)
	e := asOutErr(t, err)
	if e.Code != "KEY_PASSPHRASE_REQUIRED" || !strings.Contains(e.Message, "security key") || !strings.Contains(e.Hint, "ssh-add") {
		t.Fatalf("no agent: %+v", e)
	}
}
