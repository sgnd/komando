package cli

import (
	"io"
	"testing"
)

// TestExecuteRunsBegin goes through the real entry, execute(tcl, ...) (as the
// program does), not through begin: whatever builds a command's hooks must
// still start it with no answer left from the command before. The test of
// begin alone would not see execute dropping that call.
func TestExecuteRunsBegin(t *testing.T) {
	invHome(t)
	noAgent(t)
	saved := tcl.out.W
	tcl.out.W = io.Discard
	t.Cleanup(func() { tcl.out.W = saved })

	t.Run("a command starts with no answer from the one before", func(t *testing.T) {
		tcl.sess.ConfirmDanger("host rm web1")
		tcl.sess.SetAllowed(true)
		tcl.ttyYes = []string{"web1"}
		if code := executeArgs([]string{"version"}); code != 0 {
			t.Fatalf("komando version: exit %d", code)
		}
		if tcl.sess.DangerConfirmed("host rm web1") || tcl.sess.Allowed() || tcl.ttyYes != nil {
			t.Errorf("an answer from before the command stayed: confirmed %v, allowed %v, ttyYes %v",
				tcl.sess.DangerConfirmed("host rm web1"), tcl.sess.Allowed(), tcl.ttyYes)
		}
	})

	t.Run("a command the person answered does not answer the next one", func(t *testing.T) {
		mustRun(t, "host", "add", "web1", "u@127.0.0.1:1", "--protected")
		setCallerEnv(t, "KOMANDO_AGENT", "1")
		asks := 0
		tcl.ask = func(string) (allowed, shown bool) { asks++; return true, true }
		t.Cleanup(func() { tcl.ask = nil })
		if code := executeArgs([]string{"host", "rm", "web1", "--yes"}); code != 0 {
			t.Fatalf("host rm web1: exit %d", code)
		}
		if asks != 1 || !tcl.sess.Allowed() {
			t.Fatalf("the first command: asked %d times, allowed %v; want one question and a yes", asks, tcl.sess.Allowed())
		}
		if code := executeArgs([]string{"version"}); code != 0 {
			t.Fatalf("komando version: exit %d", code)
		}
		if tcl.sess.Allowed() {
			t.Error("the yes of the first command was still there when the second command ended: it started with it")
		}
	})
}
