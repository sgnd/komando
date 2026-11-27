package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/vault"
)

// A name that was free when the person started typing is stored only if it
// is still free: a secret made meanwhile (another tab, an app's
// `secret set --new`) is never replaced, for --ask-password and --ask-psk.
func TestAskSecretNeverReplacesOneMadeWhileTyping(t *testing.T) {
	invHome(t)
	saved, savedInteractive := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = saved, savedInteractive })
	tcl.terminal = true
	for _, tc := range []struct {
		sec  string
		args []string
	}{
		{"vps7-pass", []string{"host", "ssh", "add", "vps7", "root@10.0.0.70", "--ask-password"}},
		{"app7-pass", []string{"conn", "add", "app7", "postgres://app@10.0.0.71/app", "--ask-password"}},
	} {
		readPassword = func(*call, string) (string, error) {
			setSecret(t, tc.sec, "made-meanwhile") // stored while the person types
			return "Typed-Pass-7", nil
		}
		e := wantCode(t, "SECRET_EXISTS", tc.args...)
		if !strings.Contains(e.Message, "while you typed") || !strings.Contains(e.Hint, "komando secret set") {
			t.Errorf("%s: %+v", tc.sec, e)
		}
		if v, _ := vault.Get(tc.sec); v != "made-meanwhile" {
			t.Errorf("%s was replaced: %q", tc.sec, v)
		}
	}
}
