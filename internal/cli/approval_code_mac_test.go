package cli

import (
	"bytes"
	"encoding/base32"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// C160 D: on macOS the approval window takes the code in a secure field;
// komando checks it, and "Allow once" counts only with the right, unused
// code. The window here is a stand-in: no osascript runs.
func TestMacWindowCode(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long")
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	secret := []byte("12345678901234567890")
	if err := vault.Set(store.Save(), approvalSecret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	var errb bytes.Buffer
	savedOS, savedMac, savedA, savedErr := desktopOS, askMac, askOnScreen, tcl.out.Err
	t.Cleanup(func() {
		desktopOS, askMac, askOnScreen, tcl.out.Err = savedOS, savedMac, savedA, savedErr
		tcl.flags.yes = false
		resetApproval()
	})
	desktopOS, tcl.out.Err = "darwin", &errb
	askOnScreen = func(*call, string) (bool, bool) { t.Error("the window without the field was used"); return true, true }
	good := totp(secret, time.Now().Unix()/30)
	ask := func(out string) bool {
		askMac = func(v approvalView) (string, bool, bool, bool) {
			if !v.Code {
				t.Error("no code field")
			}
			c, a, g := macAnswer([]byte(out))
			return c, a, g, true
		}
		resetApproval()
		tcl.flags.yes = true
		return tcl.yesOK()
	}
	for _, out := range []string{"Allow once\n123456\n", "Allow once\n\n", "Allow once\n", "Deny\n", "gave up\n", "Deny\n" + good + "\n"} {
		if ask(out) {
			t.Errorf("%q allowed", out)
		}
	}
	if !ask("Allow once\n" + good + "\n") {
		t.Fatal("the right code was refused")
	}
	if ask("Allow once\n"+good+"\n") || tcl.sess.Window().Why != "code-used" {
		t.Errorf("a used code: why %q", tcl.sess.Window().Why)
	}
	// the code shows nowhere komando writes
	if strings.Contains(errb.String(), good) {
		t.Error("the code is in the output")
	}
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(good)) {
				t.Errorf("the code is in %s", p)
			}
		}
		return nil
	})
}

// With no code set up, the macOS window stays as it was, and komando says
// once per run that the code closes the remaining gap.
func TestMacNoCodeNote(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	setCallerEnv(t, "CLAUDECODE", "1")
	var errb bytes.Buffer
	savedOS, savedA, savedErr := desktopOS, askOnScreen, tcl.out.Err
	t.Cleanup(func() {
		desktopOS, askOnScreen, tcl.out.Err = savedOS, savedA, savedErr
		tcl.flags.yes = false
		noCodeNote = sync.Once{}
		resetAccessibilityTrust()
		resetApproval()
	})
	desktopOS, tcl.out.Err, noCodeNote = "darwin", &errb, sync.Once{}
	resetAccessibilityTrust()
	shown := 0
	askOnScreen = func(*call, string) (bool, bool) { shown++; return false, true }
	for range 2 {
		resetApproval()
		tcl.flags.yes = true
		tcl.yesOK()
	}
	if shown != 2 || strings.Count(errb.String(), "komando config approval-code") != 1 {
		t.Errorf("shown %d, stderr %q", shown, errb.String())
	}
}
