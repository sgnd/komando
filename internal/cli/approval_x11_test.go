package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
)

// O4: on an X11 desktop any program can click "Allow once", so komando
// opens no click-only window there: the person needs the approval code.
func TestX11ApprovalNeedsCode(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_NO_DIALOG", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	saved, savedOS, savedAsk := os.Args, desktopOS, askOnScreen
	t.Cleanup(func() { os.Args, desktopOS, askOnScreen = saved, savedOS, savedAsk; resetApproval() })
	os.Args = []string{"komando", "host", "rm", "web1", "--yes"}
	clicked := 0
	askOnScreen = func(string) (bool, bool) { clicked++; return true, true }

	ask := func(goos, display, wayland string) *call {
		desktopOS = goos
		t.Setenv("DISPLAY", display)
		t.Setenv("WAYLAND_DISPLAY", wayland)
		c := newCall()
		c.caller = engine.Caller{Kind: engine.Agent, Agent: "Claude Code"}
		active.Store(c)
		c.personAllowsFor("--yes", "")
		return c
	}
	c := ask("linux", ":0", "")
	if c.sess.Allowed() || clicked != 0 || c.sess.Window().Why != "needs-code" {
		t.Fatalf("X11: allowed %v, clicked %d, why %q", c.sess.Allowed(), clicked, c.sess.Window().Why)
	}
	e := out.Errf(out.ExitPolicy, "PROTECTED_HOST", "add --yes", "web1 is protected")
	approvalHint(e)
	if !strings.Contains(e.Hint, "komando config approval-code") {
		t.Errorf("hint: %q", e.Hint)
	}
	// Wayland and macOS keep the click window
	if c := ask("linux", ":0", "wayland-0"); !c.sess.Allowed() || clicked != 1 {
		t.Errorf("Wayland: allowed %v, clicked %d", c.sess.Allowed(), clicked)
	}
	if c := ask("darwin", ":0", ""); !c.sess.Allowed() || clicked != 2 {
		t.Errorf("macOS: allowed %v, clicked %d", c.sess.Allowed(), clicked)
	}
	// the window's program opens on Wayland only
	env := strings.Join(dialogEnv(), "\n")
	if strings.Contains(env, "DISPLAY=:0") || !strings.Contains(env, "GDK_BACKEND=wayland") || !strings.Contains(env, "QT_QPA_PLATFORM=wayland") {
		t.Errorf("dialog env: %s", env)
	}
}
