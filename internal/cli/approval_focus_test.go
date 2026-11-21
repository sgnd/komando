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
		"refront()",
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

// Two panels (or a full-screen app) never fight over the focus: no re-front
// when another komando panel is key, at most 3 re-fronts in 10 seconds, and
// then the panel just stays ordered front.
func TestMacPanelRefrontIsCapped(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"var REFRONTS = [];",
		"now - REFRONTS[i] < 10000",
		"REFRONTS.length >= 3",
		"re-front limit",
		"'KomandoPanel'",
		"PANEL.orderFront(PANEL)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	h := s[strings.Index(s, "'windowDidResignKey:'"):]
	h = h[:strings.Index(h, "\n")]
	if !strings.Contains(h, "refront()") || !strings.Contains(h, "otherPanelIsKey()") {
		t.Errorf("the resign handler skips neither another panel nor the cap: %q", h)
	}
}

// After each re-front Allow once is held for 500 ms, so a click or key that
// meant the app that had the focus cannot answer the panel.
func TestMacPanelHoldsAllowAfterRefront(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"var HELD = false;",
		"function holdAllow()",
		"timerWithTimeIntervalRepeatsBlock(0.5, false",
		"ALLOW_BTN.enabled = SEEN",
		"HELD = true;\n  ALLOW_BTN.enabled = false;",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
	f := macFunc(t, "refront")
	if !strings.Contains(f, "holdAllow()") || strings.Index(f, "makeKeyAndOrderFront") > strings.Index(f, "holdAllow()") {
		t.Errorf("refront does not hold Allow once after bringing the panel forward:\n%s", f)
	}
}

// The panel shows over another app's full-screen Space.
func TestMacPanelJoinsFullScreenSpaces(t *testing.T) {
	want := "panel.collectionBehavior = $.NSWindowCollectionBehaviorCanJoinAllSpaces | $.NSWindowCollectionBehaviorFullScreenAuxiliary;"
	if !strings.Contains(macAlertScript, want) {
		t.Errorf("script has no %q", want)
	}
}

// The 500 ms hold cannot be skipped: reading to the end does not enable
// Allow once while it is held, and allow: ignores a press during it.
func TestMacPanelHoldCannotBeSkipped(t *testing.T) {
	s := macAlertScript
	for _, want := range []string{
		"SEEN = true; ALLOW_BTN.enabled = !HELD;",
		"if (!SEEN || HELD) return; CHOICE = 'Allow'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script has no %q", want)
		}
	}
}
