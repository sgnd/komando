package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// The questions come before the store's lock: removing a protected server
// asks once, outside the step, and the step finds that yes.
func TestAskBeforeStoreLock(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "tmp-1", "u@10.0.0.1", "--protected")
	texts := windowText(t, true) // the person says yes
	mustRun(t, "host", "rm", "tmp-*", "--yes")
	if len(*texts) != 1 {
		t.Fatalf("%d windows, want one", len(*texts))
	}
}

// A yes covers the question it answered: when another process changes the
// state between the question and the step so that the step would change
// more (a second protected server now matches), the step asks again,
// naming both, and the first yes does not cover it.
func TestStateChangedBetweenAskAndLock(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "tmp-1", "u@10.0.0.1", "--protected")
	texts := windowText(t, true)
	var inStep []string
	savedAsked, savedBefore := askedInStoreStep, beforeLock
	askedInStoreStep = func(_ *call, kind string) { inStep = append(inStep, kind) }
	beforeLock = func() {
		beforeLock = func() {}
		if err := store.Update(store.Save(), func(s *store.State) error {
			s.Hosts["tmp-2"] = &store.Host{Name: "tmp-2", Address: "10.0.0.2", User: "u", Protected: true}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { askedInStoreStep, beforeLock = savedAsked, savedBefore })
	mustRun(t, "host", "rm", "tmp-*", "--yes")
	if len(*texts) != 2 || strings.Contains((*texts)[0], "tmp-2") || !strings.Contains((*texts)[1], "tmp-2") {
		t.Fatalf("windows %q: want one for tmp-1, then one that names tmp-2", *texts)
	}
	if len(inStep) != 1 {
		t.Errorf("asked inside the step %d times, want once (the changed state)", len(inStep))
	}
}

// More commands that ask about a protected entry: each asks once, before
// the store's lock (the detector in TestMain fails any ask inside it).
func TestAskBeforeStoreLockMore(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup [][]string
		run   []string
	}{
		{"conn rm", [][]string{{"conn", "add", "lite", "sqlite:///tmp/komando-ask-first.db", "--protected"}}, []string{"conn", "rm", "lite", "--yes"}},
		{"host add over a protected one", [][]string{{"host", "add", "web", "u@10.0.0.1", "--protected"}}, []string{"host", "add", "web", "u@10.0.0.9", "--overwrite", "--yes"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			invHome(t)
			for _, s := range c.setup {
				mustRun(t, s...)
			}
			texts := windowText(t, true)
			mustRun(t, c.run...)
			if len(*texts) != 1 {
				t.Fatalf("%d windows, want one", len(*texts))
			}
		})
	}
}
