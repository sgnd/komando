package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/sgnd/komando/internal/engine"
)

// C160: on macOS an agent whose terminal has Accessibility permission can
// press "Allow once" through System Events, so komando asks for the
// approval code there, as on X11.
func TestMacAccessibilityNeedsCode(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	saved, savedOS, savedAsk, savedAX := tcl.args, desktopOS, askOnScreen, axTrustOutput
	t.Cleanup(func() {
		tcl.args, desktopOS, askOnScreen, axTrustOutput = saved, savedOS, savedAsk, savedAX
		resetAccessibilityTrust()
		resetApproval()
	})
	tcl.args = []string{"komando", "host", "rm", "web1", "--yes"}
	desktopOS = "darwin"
	clicked := 0
	askOnScreen = func(*call, string) (bool, bool) { clicked++; return true, true }

	cases := []struct {
		name     string
		out      string
		err      error
		needCode bool
	}{
		{"trusted", "true\n", nil, true},
		{"not trusted", "false\n", nil, false},
		{"error", "", errors.New("osascript failed"), true},
		{"garbage", "maybe\n", nil, true},
		{"timeout", "", context.DeadlineExceeded, true},
	}
	for _, c := range cases {
		axTrustOutput = func(context.Context) ([]byte, error) { return []byte(c.out), c.err }
		resetAccessibilityTrust()
		resetApproval()
		clicked = 0
		tcl.setCaller(engine.Caller{Kind: engine.Agent, Agent: "Claude Code"})
		tcl.personAllowsFor("--yes", "")
		if c.needCode {
			if tcl.sess.Allowed() || clicked != 0 || tcl.sess.Window().Why != "needs-code" {
				t.Errorf("%s: allowed %v, clicked %d, why %q", c.name, tcl.sess.Allowed(), clicked, tcl.sess.Window().Why)
			}
			if _, shown := askReveal(tcl, "the password of db1"); shown {
				t.Errorf("%s: the reveal window opened", c.name)
			}
		} else if !tcl.sess.Allowed() || clicked != 1 {
			t.Errorf("%s: allowed %v, clicked %d", c.name, tcl.sess.Allowed(), clicked)
		}
	}
}

func TestAccessibilityTrustCached(t *testing.T) {
	savedAX := axTrustOutput
	t.Cleanup(func() { axTrustOutput = savedAX; resetAccessibilityTrust() })
	runs := 0
	axTrustOutput = func(ctx context.Context) ([]byte, error) {
		runs++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("no timeout")
		}
		return []byte("false"), nil
	}
	resetAccessibilityTrust()
	first, second := accessibilityTrusted(), accessibilityTrusted()
	if first || second || runs != 1 {
		t.Errorf("runs %d", runs)
	}
}
