//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sealfile"
)

// sealWait is how long a sealed export or import may take in these tests:
// the passphrase's key derivation is slow on purpose (exitWithin).
const sealWait = 5 * time.Minute

// A person types the passphrase at the terminal, hidden: twice to seal,
// once to open on the other computer. Neither the passphrase nor a secret
// shows on the screen.
func TestPTYExportSealed(t *testing.T) {
	sealLab(t)
	file := filepath.Join(t.TempDir(), "move.kmdseal")
	p := startPTY(t, "export", "--sealed", "--with-keys", "--to", file)
	p.answer("Passphrase (hidden): ", sealPass+"\r")
	p.answer("Type it again (hidden): ", sealPass+"\r")
	if code := p.exitWithin(sealWait); code != 0 {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
	p.waitFor("check phrase: ")
	screen := p.shown()
	if strings.Contains(screen, sealPass) || strings.Contains(screen, "s3cret") || !strings.Contains(screen, "sealed 2 servers, 1 conn") ||
		!strings.Contains(screen, "Next: komando import komando "+file) {
		t.Errorf("the screen:\n%s", screen)
	}
	invHome(t)
	i := startPTY(t, "import", "komando", file)
	i.answer("Passphrase of move.kmdseal (hidden): ", sealPass+"\r")
	if code := i.exitWithin(sealWait); code != 0 {
		t.Fatalf("import: exit %d; the screen:\n%s", code, i.shown())
	}
	i.waitFor("keys added: deploy")
	screen = i.shown()
	if strings.Contains(screen, sealPass) || strings.Contains(screen, "s3cret") || !strings.Contains(screen, "servers added: web1, web2") ||
		!strings.Contains(screen, "logins stored in the vault: shop-pass, web1-pass") {
		t.Errorf("import, the screen:\n%s", screen)
	}
}

// The phone's key and its key check are typed at the terminal.
func TestPTYExportForPhone(t *testing.T) {
	sealLab(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "phone.kmdseal")
	// a key file, as the phone shares it: the key as text is longer than a
	// terminal line takes
	keyFile := filepath.Join(dir, "phone.key")
	if err := os.WriteFile(keyFile, []byte(strings.Repeat("ab", sealfile.PublicKeySize)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := startPTY(t, "export", "--for-phone", "--to", file)
	p.answer("Key file from the phone (or the key as text): ", keyFile+"\r")
	p.answer("Key check the phone shows: ", "0000\r")
	if code := p.exit(); code == 0 || !strings.Contains(p.shown(), "PHONE_KEY_INVALID") && !strings.Contains(p.shown(), "does not match the key check") {
		t.Fatalf("exit %d; the screen:\n%s", code, p.shown())
	}
}
