package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// keyFileWithCert writes a private key to dir/name and, signed by a new
// CA, a user certificate valid from after to before; it returns the key
// path and the certificate text.
func keyFileWithCert(t *testing.T, dir, name string, after, before time.Time) (string, []byte) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	_, capriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(capriv)
	c := &ssh.Certificate{Key: s.PublicKey(), CertType: ssh.UserCert, KeyId: name, ValidPrincipals: []string{"deploy"},
		ValidAfter: uint64(after.Unix()), ValidBefore: uint64(before.Unix())}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return p, ssh.MarshalAuthorizedKey(c)
}

// key add notes a certificate next to the key (logins use it as ssh
// does) and keeps the path of one named with --cert; a certificate for
// another key is refused, an out-of-date one warns.
func TestKeyAddCert(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	now := time.Now()
	p, cert := keyFileWithCert(t, dir, "id_a", now.Add(-time.Hour), now.Add(time.Hour))
	os.WriteFile(p+"-cert.pub", cert, 0o644)
	d := mustRun(t, "key", "add", "a", p)
	if d["cert_path"] != nil || d["warnings"] != nil {
		t.Errorf("a cert next to the key needs no path: %v", d)
	}

	other := filepath.Join(dir, "elsewhere-cert.pub")
	p2, cert2 := keyFileWithCert(t, dir, "id_b", now.Add(-time.Hour), now.Add(time.Hour))
	os.WriteFile(other, cert2, 0o644)
	if d := mustRun(t, "key", "add", "b", p2, "--cert", other); d["cert_path"] != other {
		t.Errorf("--cert path not kept: %v", d)
	}
	wantCode(t, "KEY_INVALID", "key", "add", "c", p, "--cert", other) // b's certificate for a's key

	p3, old := keyFileWithCert(t, dir, "id_d", now.Add(-2*time.Hour), now.Add(-time.Hour))
	os.WriteFile(p3+"-cert.pub", old, 0o644)
	d = mustRun(t, "key", "add", "d", p3)
	if w, _ := d["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "not valid now") {
		t.Errorf("an old certificate: %v", d)
	}

	// key edit gives a key a certificate and takes it away
	wantCode(t, "KEY_INVALID", "key", "edit", "a", "--cert", other)
	os.WriteFile(filepath.Join(dir, "a-elsewhere-cert.pub"), cert, 0o644)
	if d := mustRun(t, "key", "edit", "a", "--cert", filepath.Join(dir, "a-elsewhere-cert.pub")); d["action"] != "changed" {
		t.Errorf("edit --cert: %v", d)
	}
	if d := mustRun(t, "key", "edit", "a", "--unset", "cert"); d["action"] != "changed" || d["cert_path"] != nil {
		t.Errorf("edit --unset cert: %v", d)
	}
}
