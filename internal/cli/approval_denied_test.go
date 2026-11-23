package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// The panel prints "Deny key" for Esc and Cmd-W and "Deny" for a click on
// Deny or the close button; anything else stays a Deny.
func TestMacAnswerNamesKeyDeny(t *testing.T) {
	for in, want := range map[string]macOutcome{
		"Deny\n":     macDenied,
		"Deny key\n": macDeniedKey,
		"Deny keys":  macDenied,
	} {
		if got := macAnswer([]byte(in)); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

// The agent learns how the person said no: a click on Deny, or a key (Esc,
// Cmd-W) that may have been pressed by mistake.
func TestDeniedByInError(t *testing.T) {
	for _, c := range []struct {
		outcome macOutcome
		by      string
		hint    string
	}{
		{macDenied, "click", "the user clicked Deny"},
		{macDeniedKey, "key", "closed komando's window with Esc or Cmd-W"},
	} {
		asAgent(t, false, true)
		resetApproval()
		askMac = func(approvalView, io.Writer) (macOutcome, bool) { return c.outcome, true }
		allowed, shown := askMacWindow(tcl, "echo hi")
		if allowed || !shown {
			t.Fatalf("%s: allowed %v, shown %v", c.by, allowed, shown)
		}
		if tcl.sess.Window().Why == "" {
			tcl.sess.SetWhy("denied") // what ask does for a window that was shown and not allowed
		}
		e := &out.Error{Code: "PROTECTED_TARGET", Hint: "ask", Exit: out.ExitPolicy}
		approvalHint(tcl, e)
		d, _ := e.Details.(map[string]string)
		if d["denied_by"] != c.by {
			t.Errorf("%s: details %v, want denied_by %q", c.by, e.Details, c.by)
		}
		if !strings.Contains(e.Hint, c.hint) {
			t.Errorf("%s: hint %q, want %q", c.by, e.Hint, c.hint)
		}
		if e.Code != "PROTECTED_TARGET" {
			t.Errorf("%s: code changed to %s", c.by, e.Code)
		}
	}
}
