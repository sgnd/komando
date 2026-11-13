package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// key add takes a security key (FIDO2) file: Go cannot read its key
// handle, so the public key comes from FILE.pub, and the warning says
// komando signs with it through ssh-agent.
func TestKeyAddSecurityKey(t *testing.T) {
	invHome(t)
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	pubBlob := ssh.Marshal(struct{ Type, Key, App string }{"sk-ssh-ed25519@openssh.com", string(pubKey), "ssh:"})
	pub, err := ssh.ParsePublicKey(pubBlob)
	if err != nil {
		t.Fatal(err)
	}
	priv := ssh.Marshal(struct {
		Check1, Check2 uint32
		Keytype        string
		Rest           []byte `ssh:"rest"`
	}{3, 3, "sk-ssh-ed25519@openssh.com", []byte("handle")})
	for i := byte(1); len(priv)%8 != 0; i++ {
		priv = append(priv, i)
	}
	body := append([]byte("openssh-key-v1\x00"), ssh.Marshal(struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}{"none", "none", "", 1, pubBlob, priv})...)
	p := filepath.Join(t.TempDir(), "id_ed25519_sk")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body}), 0o600)
	os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(pub), 0o644)
	d := mustRun(t, "key", "add", "yubi", p)
	w, _ := d["warnings"].([]any)
	if d["type"] != "sk-ssh-ed25519@openssh.com" || d["fingerprint"] != ssh.FingerprintSHA256(pub) || len(w) != 1 || !strings.Contains(w[0].(string), "ssh-add") {
		t.Errorf("key add: %v", d)
	}
	os.Remove(p + ".pub")
	wantCode(t, "KEY_INVALID", "key", "add", "yubi2", p) // without .pub it cannot be told apart
}
