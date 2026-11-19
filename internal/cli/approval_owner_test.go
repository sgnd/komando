package cli

import (
	"encoding/base32"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// C187: on macOS "Allow once" counts only after the device-owner check
// (Touch ID or the login password) in the same osascript run. The window
// here is a stand-in: no osascript runs and no prompt shows.
func TestMacDeviceOwner(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	setCallerEnv(t, "CLAUDECODE", "1")
	saved, savedOS, savedMac, savedA := tcl.args, desktopOS, askMac, askOnScreen
	t.Cleanup(func() {
		tcl.args, desktopOS, askMac, askOnScreen = saved, savedOS, savedMac, savedA
		tcl.flags.yes = false
		resetAccessibilityTrust()
		resetApproval()
	})
	tcl.args = []string{"komando", "host", "rm", "web-1.example.test", "--yes"}
	desktopOS, askOnScreen = "darwin", askMacWindow
	resetAccessibilityTrust()
	var seen approvalView
	ask := func(out string) (bool, string) {
		askMac = func(v approvalView) (macOutcome, bool) { seen = v; return macAnswer([]byte(out)), true }
		resetApproval()
		tcl.flags.yes = true
		ok := tcl.yesOK("it runs on web-1.example.test")
		return ok, tcl.sess.Window().Why
	}
	if ok, _ := ask("Allow once\nowner ok\n"); !ok {
		t.Fatal("Allow once with the owner confirmed was refused")
	}
	for out, why := range map[string]string{
		"Allow once\nowner denied\n":      "owner-failed",
		"Allow once\nowner timeout\n":     "owner-failed",
		"Allow once\nowner unavailable\n": "owner-failed",
		"Allow once\n":                    "owner-failed",
		"Allow once\nsomething else\n":    "owner-failed",
		"Allow once":                      "denied",
		"Deny\n":                          "denied",
		"":                                "denied",
		"gave up\n":                       "no-answer",
	} {
		if ok, got := ask(out); ok || got != why {
			t.Errorf("%q: allowed %v, why %q, want %q", out, ok, got, why)
		}
	}
	// the reason names the target and goes in through argv after the marker
	args := macArgs(seen)
	if args[4] != macArgMarker || args[12] != "komando: allow web-1.example.test" {
		t.Errorf("argv %q", args[4:])
	}
	if strings.Contains(macAlertScript, "web-1.example.test") || strings.Contains(args[3], "web-1") {
		t.Error("the target is in the script")
	}
	// the owner check runs only on the Allow once branch: Deny never calls it
	if strings.Count(macAlertScript, "owner(argv[8], until)") != 1 || strings.Count(macAlertScript, "evaluatePolicyLocalizedReasonReply") != 1 {
		t.Error("the owner check is called outside the Allow once branch")
	}
	deny := macAlertScript[strings.Index(macAlertScript, "if (r === $.NSAlertFirstButtonReturn)"):]
	if strings.Contains(deny, "owner(") {
		t.Error("Deny calls the owner check")
	}
}

// On macOS an approval code that is on does not change the window: the
// device-owner check replaces it, and the code field never opens.
func TestMacIgnoresApprovalCode(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long")
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	if err := vault.Set(store.Save(), approvalSecret, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(store.Save(), func(st *store.State) error { st.Settings.ApprovalCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	savedOS, savedMac, savedA, savedCode := desktopOS, askMac, askOnScreen, askCodeOnScreen
	t.Cleanup(func() {
		desktopOS, askMac, askOnScreen, askCodeOnScreen = savedOS, savedMac, savedA, savedCode
		tcl.flags.yes = false
		resetAccessibilityTrust()
		resetApproval()
	})
	desktopOS, askOnScreen = "darwin", askMacWindow
	resetAccessibilityTrust()
	askCodeOnScreen = func(*call, string) (string, bool, bool) {
		t.Error("the code window opened on macOS")
		return "", true, true
	}
	shown := 0
	askMac = func(approvalView) (macOutcome, bool) { shown++; return macAllowed, true }
	resetApproval()
	tcl.flags.yes = true
	if !tcl.yesOK() || shown != 1 {
		t.Errorf("shown %d", shown)
	}
}
