package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
)

// O4: on an X11 desktop any program can click "Allow once", and on
// Wayland the agent can point WAYLAND_DISPLAY at a compositor of its own
// and click there, so komando opens no click-only window on a Linux or
// BSD desktop: the person needs the approval code.
func TestX11ApprovalNeedsCode(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	saved, savedOS, savedAsk := tcl.args, desktopOS, askOnScreen
	t.Cleanup(func() { tcl.args, desktopOS, askOnScreen = saved, savedOS, savedAsk; resetApproval() })
	tcl.args = []string{"komando", "host", "rm", "web1", "--yes"}
	clicked := 0
	askOnScreen = func(*call, string) (bool, bool) { clicked++; return true, true }

	ask := func(goos, display, wayland string) *call {
		desktopOS = goos
		t.Setenv("DISPLAY", display)
		t.Setenv("WAYLAND_DISPLAY", wayland)
		resetApproval()
		tcl.setCaller(engine.Caller{Kind: engine.Agent, Agent: "Claude Code"})
		tcl.personAllowsFor("--yes", "")
		return tcl
	}
	c := ask("linux", ":0", "")
	if c.sess.Allowed() || clicked != 0 || c.sess.Window().Why != "needs-code" {
		t.Fatalf("X11: allowed %v, clicked %d, why %q", c.sess.Allowed(), clicked, c.sess.Window().Why)
	}
	e := out.Errf(out.ExitPolicy, "PROTECTED_HOST", "add --yes", "web1 is protected")
	approvalHint(tcl, e)
	if !strings.Contains(e.Hint, "komando config approval-code") {
		t.Errorf("hint: %q", e.Hint)
	}
	// Wayland too: the agent sets WAYLAND_DISPLAY
	if c := ask("linux", "", "wayland-agent"); c.sess.Allowed() || clicked != 0 || c.sess.Window().Why != "needs-code" {
		t.Errorf("Wayland: allowed %v, clicked %d, why %q", c.sess.Allowed(), clicked, c.sess.Window().Why)
	}
	if c := ask("freebsd", ":0", "wayland-0"); c.sess.Allowed() || clicked != 0 {
		t.Errorf("BSD: allowed %v, clicked %d", c.sess.Allowed(), clicked)
	}
	// macOS keeps the click window
	if c := ask("darwin", ":0", ""); !c.sess.Allowed() || clicked != 1 {
		t.Errorf("macOS: allowed %v, clicked %d", c.sess.Allowed(), clicked)
	}
}
