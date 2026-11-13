package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/sshx"
)

// Only a person at a terminal is asked what an SSH login wants (a password,
// a two-factor code). AI agents and scripts get NO_AUTH or AUTH_FAILED with
// a hint instead, so nothing waits on a question nobody sees.
func TestSSHLoginAsksOnlyAPerson(t *testing.T) {
	invHome(t)
	saved := interactive
	t.Cleanup(func() { interactive = saved; sshx.Ask = nil })

	mustRun(t, "list")
	if sshx.Ask != nil {
		t.Fatal("a script would be asked")
	}
	interactive = func() bool { return true }
	mustRun(t, "list")
	if sshx.Ask == nil {
		t.Fatal("a person at the terminal is not asked")
	}
	interactive = saved
	mustRun(t, "list")
	if sshx.Ask != nil {
		t.Fatal("the question stays on for the next command")
	}
}
