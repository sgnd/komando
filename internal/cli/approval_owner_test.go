package cli

import (
	"context"
	"encoding/base32"
	"errors"
	"io"
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
		setGate(tcl, false, gateYes)
		resetAccessibilityTrust()
		resetApproval()
	})
	tcl.args = []string{"komando", "host", "ssh", "remove", "web-1.example.test", "--yes"}
	desktopOS, askOnScreen = "darwin", askMacWindow
	resetAccessibilityTrust()
	var seen approvalView
	ask := func(out string) (bool, string) {
		askMac = func(v approvalView, _ io.Writer) (macOutcome, bool) { seen = v; return macAnswer([]byte(out)), true }
		resetApproval()
		setGate(tcl, true, gateYes)
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
		"":                                "window-failed",
		"gave up\n":                       "no-answer",
	} {
		if ok, got := ask(out); ok || got != why {
			t.Errorf("%q: allowed %v, why %q, want %q", out, ok, got, why)
		}
	}
	// the reason names the target and goes in through argv after the marker
	args := macArgs(seen)
	if args[4] != macArgMarker || args[7] != "komando: allow web-1.example.test" {
		t.Errorf("argv %q", args[4:])
	}
	if strings.Contains(macAlertScript, "web-1.example.test") || strings.Contains(args[3], "web-1") {
		t.Error("the target is in the script")
	}
	// the owner check runs only on the Allow once branch: Deny never calls it
	if strings.Count(macAlertScript, "owner(argv[3], argv[4])") != 1 || strings.Count(macAlertScript, "evaluatePolicyLocalizedReasonReply") != 1 {
		t.Error("the owner check is called outside the Allow once branch")
	}
	deny := macAlertScript[strings.Index(macAlertScript, "if (CHOICE === 'gave up')"):]
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
		setGate(tcl, false, gateYes)
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
	askMac = func(approvalView, io.Writer) (macOutcome, bool) { shown++; return macAllowed, true }
	resetApproval()
	setGate(tcl, true, gateYes)
	if !tcl.yesOK() || shown != 1 {
		t.Errorf("shown %d", shown)
	}
}

// C187 L2: the owner check has its own 50 s, passed in argv; the window
// and the check together stay inside macWindowTimeout.
func TestMacOwnerTimeoutBound(t *testing.T) {
	args := macArgs(approvalView{raw: "t"})
	if args[8] != "50" || windowGiveUp+ownerTimeout > macWindowTimeout {
		t.Errorf("owner bound %q, window %v + %v > %v", args[8], windowGiveUp, ownerTimeout, macWindowTimeout)
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
	askMac = func(v approvalView, _ io.Writer) (macOutcome, bool) { *seen = v; return ans, true }
	return seen
}

// C187 L1: a reveal's owner prompt names the secret, quoted when its
// name does not show as itself.
func TestMacRevealOwnerReason(t *testing.T) {
	seen := revealSetup(t, "false\n", macAllowed)
	if ok, _ := askReveal(tcl, "credential:db-pass"); !ok || seen.ownerReason() != "komando: show credential:db-pass" {
		t.Errorf("allowed %v, reason %q", ok, seen.ownerReason())
	}
	resetApproval()
	askReveal(tcl, "credential:a\u202eb")
	if r := seen.ownerReason(); r != "komando: show \"credential:a\\u202eb\"" {
		t.Errorf("reason %q", r)
	}
	if args := macArgs(*seen); strings.Contains(args[3], "credential:") {
		t.Error("the secret name is in the script")
	}
}

// C187 L3: a reveal says why it stopped: an Accessibility-trusted terminal,
// a failed owner check, or one nobody confirmed in time.
func TestMacRevealReasons(t *testing.T) {
	gate := func() *out.Error {
		_, err := revealGate(tcl, "secret.show", "secret", "db-pass", "credential:db-pass")
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

// An Accessibility-trusted terminal gets the window when the device-owner
// check can run (a click cannot answer it), and "Allow once" still needs
// "owner ok". Where the check cannot run, or its answer is anything but
// "true", komando refuses with ax-trusted, for --yes and for a reveal.
func TestMacAXTrustedOwnerCheck(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	saved, savedOS, savedMac, savedA, savedAX, savedOC, savedFrom := tcl.args, desktopOS, askMac, askOnScreen, axTrustOutput, ownerCheckOutput, startedFrom
	t.Cleanup(func() {
		tcl.args, desktopOS, askMac, askOnScreen, axTrustOutput, ownerCheckOutput, startedFrom = saved, savedOS, savedMac, savedA, savedAX, savedOC, savedFrom
		setGate(tcl, false, gateYes)
		resetAccessibilityTrust()
		resetOwnerCheck()
		resetApproval()
	})
	tcl.args = []string{"komando", "host", "ssh", "remove", "web-1.example.test", "--yes"}
	desktopOS, askOnScreen = "darwin", askMacWindow
	startedFrom = func(*call) string { return "" }
	axTrustOutput = func(context.Context) ([]byte, error) { return []byte("true\n"), nil }
	shown := 0
	try := func(oc string, ocErr error, ans macOutcome) (yes, reveal bool, why, revealWhy string) {
		ownerCheckOutput = func(context.Context) ([]byte, error) { return []byte(oc), ocErr }
		askMac = func(approvalView, io.Writer) (macOutcome, bool) { shown++; return ans, true }
		resetAccessibilityTrust()
		resetOwnerCheck()
		resetApproval()
		setCallerEnv(t, "CLAUDECODE", "1")
		setGate(tcl, true, gateYes)
		yes, why = tcl.yesOK(), tcl.sess.Window().Why
		setGate(tcl, false, gateYes)
		t.Setenv("CLAUDECODE", "")
		resetApproval()
		reveal, _ = askReveal(tcl, "credential:db-pass")
		return yes, reveal, why, tcl.sess.Window().Why
	}
	shown = 0
	if yes, reveal, _, _ := try("true\n", nil, macAllowed); !yes || !reveal || shown != 2 {
		t.Errorf("owner check available: yes %v, reveal %v, shown %d", yes, reveal, shown)
	}
	shown = 0
	if yes, reveal, why, _ := try("true\n", nil, macOwnerFailed); yes || reveal || shown != 2 || why != "owner-failed" {
		t.Errorf("owner not confirmed: yes %v, reveal %v, shown %d, why %q", yes, reveal, shown, why)
	}
	for name, c := range map[string]struct {
		out string
		err error
	}{"false": {"false\n", nil}, "error": {"", errors.New("osascript failed")}, "timeout": {"", context.DeadlineExceeded},
		"garbage": {"maybe\n", nil}, "upper": {"TRUE\n", nil}, "empty": {"", nil}} {
		shown = 0
		yes, reveal, why, revealWhy := try(c.out, c.err, macAllowed)
		if yes || reveal || shown != 0 || why != "ax-trusted" || revealWhy != "ax-trusted" {
			t.Errorf("%s: yes %v, reveal %v, shown %d, why %q/%q", name, yes, reveal, shown, why, revealWhy)
		}
	}
}

func TestOwnerCheckCached(t *testing.T) {
	saved := ownerCheckOutput
	t.Cleanup(func() { ownerCheckOutput = saved; resetOwnerCheck() })
	runs := 0
	ownerCheckOutput = func(ctx context.Context) ([]byte, error) {
		runs++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("no timeout")
		}
		return []byte("true\n"), nil
	}
	resetOwnerCheck()
	first, second := ownerCheckAvailable(), ownerCheckAvailable()
	if !first || !second || runs != 1 {
		t.Errorf("runs %d", runs)
	}
}
