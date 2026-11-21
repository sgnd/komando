package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// A panel that crashed or never answered is not a Deny: osascript's error
// exit and an empty answer are their own outcome, a start failure still
// shows no window.
func TestMacWindowFailureIsNotDeny(t *testing.T) {
	if got, shown := macResult(nil, exitStatus2(t)); got != macFailed || !shown {
		t.Errorf("error exit: %v, shown %v, want macFailed, true", got, shown)
	}
	if got := macAnswer(nil); got != macFailed {
		t.Errorf("empty answer: %v, want macFailed", got)
	}
	if got := macAnswer([]byte("Deny\n")); got != macDenied {
		t.Errorf("Deny: %v, want macDenied", got)
	}
}

// The window failing gets its own reason, error code and hint; the hint
// never says the user clicked Deny.
func TestWindowFailedHint(t *testing.T) {
	for _, agent := range []bool{true, false} {
		if agent {
			asAgent(t, false, true)
		} else {
			noAgent(t)
		}
		resetApproval()
		askMac = func(approvalView, io.Writer) (macOutcome, bool) { return macFailed, true }
		allowed, shown := askMacWindow(tcl, "echo hi")
		if allowed || !shown || tcl.sess.Window().Why != "window-failed" {
			t.Fatalf("allowed %v, shown %v, why %q", allowed, shown, tcl.sess.Window().Why)
		}
		e := &out.Error{Code: "PROTECTED_TARGET", Hint: "ask", Exit: out.ExitPolicy}
		approvalHint(tcl, e)
		if e.Code != "APPROVAL_WINDOW_FAILED" || strings.Contains(e.Hint, "the user clicked Deny") || !strings.Contains(e.Hint, "update komando") {
			t.Errorf("agent %v: code %q, hint %q", agent, e.Code, e.Hint)
		}
	}
}

// The panel stays open when another app takes the focus: it does not hide
// on deactivation, comes back to the front when it stops being key, and
// only the buttons, Esc, Return, the close button and the 120 s timer end
// it.
func TestMacPanelStaysOpenOnFocusLoss(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"panel.hidesOnDeactivate = false",
		"'windowDidResignKey:'",
		"PANEL.makeKeyAndOrderFront(PANEL)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	h := s[strings.Index(s, "'windowDidResignKey:'"):]
	h = h[:strings.Index(h, "\n")]
	if strings.Contains(h, "stopModal") {
		t.Errorf("losing key ends the panel: %q", h)
	}
}
