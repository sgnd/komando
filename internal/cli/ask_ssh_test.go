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
	saved := tcl.terminal
	t.Cleanup(func() { tcl.terminal = saved })

	mustRun(t, "list")
	if sshx.Asker() != nil {
		t.Fatal("a script would be asked")
	}
	tcl.terminal = true
	mustRun(t, "list")
	if sshx.Asker() == nil {
		t.Fatal("a person at the terminal is not asked")
	}
	tcl.terminal = saved
	mustRun(t, "list")
	if sshx.Asker() != nil {
		t.Fatal("the question stays on for the next command")
	}
	// with a second call running, neither is asked: the question could
	// reach the wrong one
	tcl.terminal = true
	other := testCall()
	other.enter()
	defer other.leave()
	if sshx.Asker() != nil {
		t.Fatal("a person is asked while another call runs")
	}
}
