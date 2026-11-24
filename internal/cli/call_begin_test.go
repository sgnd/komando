package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/engine"
)

// TestBeginResetsBetweenCalls: begin starts a command in a call that ran
// one before: the caller is read again, no answer given so far counts (the
// approval window's state, a safety change or a danger a person allowed, a
// no), and what the last command typed or read is forgotten, the typed
// passwords zeroed. Whatever builds the next command's hooks must keep
// this, or an approval would carry into the next command of the call.
func TestBeginResetsBetweenCalls(t *testing.T) {
	cl := testCall()
	cl.setCaller(engine.Caller{Kind: engine.Agent, Agent: "a previous agent"})
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

	cl.begin()

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
