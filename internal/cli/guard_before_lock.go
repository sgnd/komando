package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// storeUpdate is store.Update for a command. While fn runs, the store's
// write step and its lock are held, so every other komando process waits:
// nothing in fn may wait on a person (askedInStoreStep).
func storeUpdate(cl *call, fn func(*store.State) error) error {
	return store.Update(cl.storeWrite(), fn)
}

// askedInStoreStep is told when a person is about to be asked (the approval
// window or a terminal question) from inside a store step. Asking there
// holds the store for as long as the person takes; a command asks before
// the lock and only re-checks the answer inside it. Production still asks
// and notes it in the debug log; the tests fail on it.
var askedInStoreStep = func(cl *call, kind string) {
	if w := openApprovalDebug(cl); w != nil {
		fmt.Fprintf(w, "asked a person inside a store step: %s (%s)\n", komandoVerb(cl), kind)
		w.Close()
	}
}

// komandoVerb is the command's own words, without its arguments: the
// debug log never holds what the person was shown.
func komandoVerb(cl *call) string {
	var words []string
	for _, a := range cl.args[1:] {
		if strings.HasPrefix(a, "-") || len(words) == 2 {
			break
		}
		words = append(words, a)
	}
	return "komando " + strings.Join(words, " ")
}

// noteAsk tells askedInStoreStep when this goroutine is inside a store
// step: storeUpdate is on its own stack. Other goroutines' steps (a
// background job's) do not count.
func noteAsk(cl *call, what string) {
	if inStoreStep() {
		cl.askedInStep = true // the audit record says so (askedInStoreStep is quiet in a run)
		askedInStoreStep(cl, what)
	}
}

func inStoreStep() bool {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		f, more := frames.Next()
		if strings.HasSuffix(f.Function, "internal/cli.storeUpdate") {
			return true
		}
		if !more {
			return false
		}
	}
}

// updateAskFirst is storeUpdate for a step whose fn only reads and changes
// the state it is given, and sets the values it reports afresh on each run
// (no files, vault, network, or objects from outside the state). fn runs
// once on a loaded copy before the lock, so every question is asked there;
// inside the lock it runs again, and a yes to the same question about the
// same targets is remembered. A state that changed in between asks again.
func updateAskFirst(cl *call, fn func(*store.State) error) error {
	if err := askFirst(cl, fn); err != nil {
		return err
	}
	return storeUpdate(cl, fn)
}

// beforeLock runs between the questions and the store step; a test puts
// another process's change there.
var beforeLock = func() {}

// askFirst runs check on a loaded copy of the state, outside the store's
// lock: the questions a step would ask are asked here. A store that cannot
// be read leaves the questions to the step.
func askFirst(cl *call, check func(*store.State) error) error {
	st, err := loadState()
	if err != nil {
		return nil
	}
	if err := check(st); err != nil {
		return err
	}
	beforeLock()
	return nil
}
