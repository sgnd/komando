package cli

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
)

// Two commands run at once in one process, each with its own call: the
// person allows one and denies the other, and neither sees the other's
// answer (run with -race).
func TestCallsApartAtOnce(t *testing.T) {
	setHome(t, t.TempDir())
	var inside sync.WaitGroup
	inside.Add(2)
	both := make(chan struct{})
	go func() { inside.Wait(); close(both) }()

	type result struct {
		first, again bool
		asked        int
		said         *call
	}
	run := func(agent string, answer bool) result {
		c := testCall()
		c.args = []string{"komando", "host", "rm", "web1", "--yes"}
		c.setCaller(engine.Caller{Kind: engine.Agent, Agent: agent})
		var r result
		c.ask = func(text string) (bool, bool) {
			r.asked++
			inside.Done()
			select { // both windows are open at the same moment
			case <-both:
			case <-time.After(10 * time.Second):
				t.Error("the other command never asked")
			}
			return answer, true
		}
		cmd := &cobra.Command{Use: "x", SilenceErrors: true, SilenceUsage: true,
			RunE: func(cmd *cobra.Command, _ []string) error {
				own := callFrom(cmd.Context())
				r.first = own.personAllowsFor("--yes", "")
				r.again = own.personAllowsFor("--yes", "") // one answer covers the command
				r.said = own
				return nil
			}}
		cmd.SetArgs([]string{})
		if err := cmd.ExecuteContext(withCall(context.Background(), c)); err != nil {
			t.Error(err)
		}
		return r
	}

	var yes, no result
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); yes = run("Agent A", true) }()
	go func() { defer wg.Done(); no = run("Agent B", false) }()
	wg.Wait()

	if !yes.first || !yes.again || yes.asked != 1 {
		t.Errorf("allowed call: %+v", yes)
	}
	if no.first || no.again || no.asked != 1 {
		t.Errorf("denied call: %+v", no)
	}
	if yes.said == no.said || !yes.said.sess.Allowed() || no.said.sess.Allowed() || no.said.sess.Window().Why != "denied" {
		t.Error("one call's answer reached the other")
	}
}

// Building a command tree inside a running command (a guided form,
// ssh-gate) leaves the running command's call alone.
func TestNewRootKeepsTheRunningCall(t *testing.T) {
	resetApproval()
	c := tcl
	c.sess.SaidNo(true)
	newRoot(tcl)
	if tcl != c || !tcl.sess.PersonSaidNo() {
		t.Fatal("newRoot replaced the running command's answers")
	}
}

// The caller is read once per call: a later change to the environment
// (a future app hands in its own caller) does not turn a call into another.
func TestCallerFromTheCall(t *testing.T) {
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	if !tcl.isAgent() || tcl.caller().Agent == "" {
		t.Fatal("KOMANDO_AGENT=1 is not an agent")
	}
	os.Unsetenv("KOMANDO_AGENT")
	if !tcl.isAgent() {
		t.Fatal("the call's caller changed with the environment")
	}
	tcl.setCaller(engine.Caller{Kind: engine.Person})
	if tcl.isAgent() {
		t.Fatal("the call's own caller was not used")
	}
}

// "nothing was changed" only when the command saved nothing before the
// person said no.
func TestCancelledWording(t *testing.T) {
	invHome(t)
	c := testCall()
	c.sess.SaidNo(true)
	e := &out.Error{Code: "PROTECTED_HOST", Message: "web1 is protected", Exit: out.ExitPolicy}
	cancelled(c, e)
	if e.Message != "cancelled: web1 is protected; nothing was changed" || e.Hint != "run it again to be asked again" {
		t.Fatalf("before any write: %+v", e)
	}
	mustRun(t, "host", "add", "web1", "u@127.0.0.1:1") // a write in the same process
	e = &out.Error{Code: "PROTECTED_HOST", Message: "web1 is protected", Exit: out.ExitPolicy}
	cancelled(c, e)
	if e.Message != "cancelled: web1 is protected; what this command saved before the question stays" {
		t.Fatalf("after a write: %+v", e)
	}
}
