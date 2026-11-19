package cli

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"

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
		"Allow once\nowner timeout\n":     "owner-timeout",
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
	if strings.Count(macAlertScript, "owner(argv[8], argv[9])") != 1 || strings.Count(macAlertScript, "evaluatePolicyLocalizedReasonReply") != 1 {
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

// C187 L2: the owner check has its own 50 s, passed in argv; the window
// and the check together stay inside macWindowTimeout.
func TestMacOwnerTimeoutBound(t *testing.T) {
	args := macArgs(approvalView{raw: "t"})
	if args[13] != "50" || windowGiveUp+ownerTimeout > macWindowTimeout {
		t.Errorf("owner bound %q, window %v + %v > %v", args[13], windowGiveUp, ownerTimeout, macWindowTimeout)
	}
	if !strings.Contains(macAlertScript, "function owner(reason, secs)") {
		t.Error("the owner check does not take its own bound")
	}
}

// revealSetup puts tcl on macOS as a program without a terminal, with the
// window a stand-in that answers ans.
func revealSetup(t *testing.T, ax string, ans macOutcome) *approvalView {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	savedOS, savedMac, savedA, savedAX, savedFrom := desktopOS, askMac, askOnScreen, axTrustOutput, startedFrom
	t.Cleanup(func() {
		desktopOS, askMac, askOnScreen, axTrustOutput, startedFrom = savedOS, savedMac, savedA, savedAX, savedFrom
		resetAccessibilityTrust()
		resetApproval()
	})
	desktopOS, askOnScreen = "darwin", askMacWindow
	startedFrom = func(*call) string { return "" }
	axTrustOutput = func(context.Context) ([]byte, error) { return []byte(ax), nil }
	resetAccessibilityTrust()
	resetApproval()
	seen := &approvalView{}
	askMac = func(v approvalView) (macOutcome, bool) { *seen = v; return ans, true }
	return seen
}

// C187 L1: a reveal's owner prompt names the secret, quoted when its
// name does not show as itself.
func TestMacRevealOwnerReason(t *testing.T) {
	seen := revealSetup(t, "false\n", macAllowed)
	if ok, _ := askReveal(tcl, "secret:db-pass"); !ok || seen.ownerReason() != "komando: show secret:db-pass" {
		t.Errorf("allowed %v, reason %q", ok, seen.ownerReason())
	}
	resetApproval()
	askReveal(tcl, "secret:a\u202eb")
	if r := seen.ownerReason(); r != "komando: show \"secret:a\\u202eb\"" {
		t.Errorf("reason %q", r)
	}
	if args := macArgs(*seen); strings.Contains(args[3], "secret:") {
		t.Error("the secret name is in the script")
	}
}

// C187 L3: a reveal says why it stopped: an Accessibility-trusted terminal,
// a failed owner check, or one nobody confirmed in time.
func TestMacRevealReasons(t *testing.T) {
	gate := func() *out.Error {
		_, err := revealGate(tcl, "secret.show", "secret", "db-pass", "secret:db-pass")
		var e *out.Error
		if !errors.As(err, &e) {
			t.Fatalf("err %v", err)
		}
		return e
	}
	revealSetup(t, "true\n", macAllowed)
	if e := gate(); e.Code != "REVEAL_NEEDS_TERMINAL" || !strings.Contains(e.Hint, "Accessibility permission") {
		t.Errorf("ax-trusted: %s %q", e.Code, e.Hint)
	}
	revealSetup(t, "false\n", macOwnerFailed)
	if e := gate(); e.Code != "DECLINED" || !strings.Contains(e.Message, "did not confirm") {
		t.Errorf("owner-failed: %s %q", e.Code, e.Message)
	}
	revealSetup(t, "false\n", macOwnerTimeout)
	if e := gate(); e.Code != "DECLINED" || !strings.Contains(e.Message, "within 50 seconds") {
		t.Errorf("owner-timeout: %s %q", e.Code, e.Message)
	}
}
