package cli

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
)

// TestBeginResetsBetweenCalls: begin starts a command in a call that ran
// one before: the caller is read again, no answer given so far counts (the
// approval window's state, a safety change or a danger a person allowed, a
// no), and what the last command typed or read is forgotten, the typed
// passwords zeroed. Whatever builds the next command's hooks must keep
// this, or an approval would carry into the next command of the call.
func TestBeginResetsBetweenCalls(t *testing.T) {
	cl := testCall()
	setTestCaller(cl, engine.Caller{Kind: engine.Agent, Agent: "a previous agent"})
	cl.sess.SetAsked(true)
	cl.sess.SetAllowed(true)
	cl.sess.SetWhy("a reason")
	cl.sess.SetUnshown("not shown")
	cl.sess.SetGaveUp(true)
	cl.sess.MarkShown("a script")
	cl.sess.ApproveSafety("host edit web1")
	cl.sess.ConfirmDanger("host rm web1")
	cl.sess.SaidNo(true)
	cl.oldCopy.Store(true)
	cl.ttyYes = []string{"web1"}
	cl.typed = &typedSpec{}
	cl.typedProt = []string{"web1"}
	cl.body = &approvalBody{}
	cl.manifests = map[string]manifestRead{"deploy.yaml": {}}
	cl.askedInStep = true
	cl.logins.keep("web1", "secret")
	typed := cl.logins.pw["web1"]

	cl.begin(nil)

	w := cl.sess.Window()
	if w.Asked || w.Allowed || w.Why != "" || w.Unshown != "" || w.GaveUp {
		t.Errorf("the approval window kept its state: %+v", w)
	}
	if cl.sess.Shown("a script") || cl.sess.SafetyApproved("host edit web1") || cl.sess.DangerConfirmed("host rm web1") || cl.sess.PersonSaidNo() {
		t.Error("the session kept a shown script, a safety change, a danger or a no")
	}
	if cl.oldCopy.Load() {
		t.Error("oldCopy stayed on")
	}
	if cl.ttyYes != nil || cl.typed != nil || cl.typedProt != nil || cl.body != nil || cl.manifests != nil || cl.askedInStep {
		t.Errorf("what the last command typed or read stayed: ttyYes %v typed %v typedProt %v body %v manifests %v askedInStep %v",
			cl.ttyYes, cl.typed, cl.typedProt, cl.body, cl.manifests, cl.askedInStep)
	}
	if len(cl.logins.pw) != 0 {
		t.Errorf("typed passwords stayed: %d", len(cl.logins.pw))
	}
	for i, b := range typed {
		if b != 0 {
			t.Errorf("typed password byte %d was not zeroed", i)
			break
		}
	}
	if got, want := cl.caller(), cl.io.Caller(); got != want {
		t.Errorf("caller = %+v, want the call's own %+v", got, want)
	}
}

// TestBeginResetsGateFlagsBetweenCommands: the gate flags one command
// typed are its own. A call that runs a command with --yes,
// --allow-dangerous, --reveal and --dry-run, then one with none of them,
// runs the second with all four off: a long-lived call (an app, the
// interactive mode) never lets one command's --yes answer the next.
func TestBeginResetsGateFlagsBetweenCommands(t *testing.T) {
	invHome(t)
	noAgent(t)
	c := processCall()
	c.Stdout, c.Stderr = io.Discard, io.Discard
	cl := newCall(c, nil)
	run := func(args ...string) {
		t.Helper()
		defer store.Close()
		if code := execute(cl, context.Background(), args); code != 0 {
			t.Fatalf("komando %v: exit %d", args, code)
		}
	}
	run("--yes", "--allow-dangerous", "--reveal", "--dry-run", "version")
	if !cl.yes() || !cl.allowDangerous() || !cl.reveal() || !cl.dryRun() {
		t.Fatalf("the first command's gate flags: yes %v allow-dangerous %v reveal %v dry-run %v, want all on",
			cl.yes(), cl.allowDangerous(), cl.reveal(), cl.dryRun())
	}
	run("version")
	if cl.yes() || cl.allowDangerous() || cl.reveal() || cl.dryRun() {
		t.Errorf("the second command, typed without them, still had: yes %v allow-dangerous %v reveal %v dry-run %v",
			cl.yes(), cl.allowDangerous(), cl.reveal(), cl.dryRun())
	}
}

// TestBeginWhileHooksRead: the hooks of the lower packages read a running
// call's caller and gate flags from other goroutines while the call starts
// its next command (begin). Under -race this must report nothing, and each
// read sees a whole caller: an agent never reads as a person halfway.
func TestBeginWhileHooksRead(t *testing.T) {
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	cl := testCall()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if c := cl.caller(); !c.IsAgent() || c.Agent == "" {
				t.Errorf("a hook read a caller that is not the agent: %+v", c)
				return
			}
			_ = cl.dryRun() || cl.yes() || cl.allowDangerous() || cl.reveal()
		}
	}()
	for range 2000 {
		cl.begin(nil)
	}
	close(done)
	wg.Wait()
}
