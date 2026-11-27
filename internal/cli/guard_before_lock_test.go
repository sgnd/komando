package cli

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// The questions come before the store's lock: removing a protected server
// asks once, outside the step, and the step finds that yes.
func TestAskBeforeStoreLock(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "tmp-1", "u@10.0.0.1", "--protected")
	texts := windowText(t, true) // the person says yes
	mustRun(t, "host", "ssh", "remove", "tmp-*", "--yes")
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
	mustRun(t, "host", "ssh", "add", "tmp-1", "u@10.0.0.1", "--protected")
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
	mustRun(t, "host", "ssh", "remove", "tmp-*", "--yes")
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
		{"host add over a protected one", [][]string{{"host", "ssh", "add", "web", "u@10.0.0.1", "--protected"}}, []string{"host", "ssh", "add", "web", "u@10.0.0.9", "--overwrite", "--yes"}},
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

// oneByte hands out one byte per Read, so each question's own reader
// takes only its line of the answers.
type oneByte struct{ r io.Reader }

func (o oneByte) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

// typesAnswers makes tcl a person at a terminal who types answers, one line
// per question; it returns what komando wrote on stderr.
func typesAnswers(t *testing.T, answers string) *bytes.Buffer {
	t.Helper()
	var errOut bytes.Buffer
	savedIn, savedErr, savedTerm := tcl.stdin, tcl.out.Err, tcl.terminal
	tcl.stdin, tcl.out.Err, tcl.terminal = oneByte{strings.NewReader(answers)}, &errOut, true
	t.Cleanup(func() { tcl.stdin, tcl.out.Err, tcl.terminal = savedIn, savedErr, savedTerm })
	return &errOut
}

func groupNow(t *testing.T, group string) []string {
	t.Helper()
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	return groupMembersOf(st, group)
}

// inStepAsks counts the asks made inside a store step in this test
// instead of failing the package (TestMain).
func inStepAsks(t *testing.T) *[]string {
	var asked []string
	saved := askedInStoreStep
	askedInStoreStep = func(_ *call, kind string) { asked = append(asked, kind) }
	t.Cleanup(func() { askedInStoreStep = saved })
	return &asked
}

func groupOfFour(t *testing.T) {
	invHome(t)
	for i := 1; i <= 4; i++ {
		mustRun(t, "host", "ssh", "add", "h"+strconv.Itoa(i), "u@10.0.0."+strconv.Itoa(i))
	}
	mustRun(t, "group", "add", "g", "h1,h2,h3,h4")
}

// group rm of a big group asks at the terminal, before the store's lock;
// the question names the members, and a no changes nothing.
func TestGroupRmAsksBeforeLock(t *testing.T) {
	groupOfFour(t)
	errOut := typesAnswers(t, "n\n")
	if _, e := invRun(t, "group", "rm", "g"); e == nil {
		t.Fatal("the person said no, but the group was removed")
	}
	if !strings.Contains(errOut.String(), "Delete group g from 4 entries (h1, h2, h3, h4)?") {
		t.Errorf("question %q does not name the members", errOut.String())
	}
	if n := len(groupNow(t, "g")); n != 4 {
		t.Errorf("%d members after a no, want 4", n)
	}
}

// A member added between the question and the step is a new question: the
// first yes names four members and does not cover five.
func TestGroupRmMembershipChangedAsksAgain(t *testing.T) {
	groupOfFour(t)
	errOut := typesAnswers(t, "y\ny\n")
	asked := inStepAsks(t)
	savedBefore := beforeLock
	t.Cleanup(func() { beforeLock = savedBefore })
	beforeLock = func() {
		beforeLock = func() {}
		if err := store.Update(store.Save(), func(s *store.State) error {
			s.Hosts["h5"] = &store.Host{Name: "h5", Address: "10.0.0.5", User: "u", Groups: []string{"g"}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "group", "rm", "g")
	if q := strings.Count(errOut.String(), "Delete group g"); q != 2 || !strings.Contains(errOut.String(), "from 5 entries (h1, h2, h3, h4, h5)?") {
		t.Errorf("%d questions, want a second one naming h5: %q", q, errOut.String())
	}
	if len(*asked) != 1 {
		t.Errorf("asked inside the step %d times, want once (the changed group)", len(*asked))
	}
	if n := len(groupNow(t, "g")); n != 0 {
		t.Errorf("%d members left", n)
	}
}

// vpn rm of a protected VPN asks before the lock; a no changes nothing.
func TestVpnRmAsksBeforeLock(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080", "--protected")
	texts := windowText(t, false)
	if _, e := invRun(t, "vpn", "rm", "lab", "--yes"); e == nil {
		t.Fatal("the person said no, but the VPN was removed")
	}
	if len(*texts) != 1 {
		t.Errorf("%d windows, want one", len(*texts))
	}
	st, _ := loadState()
	if st.Vpns["lab"] == nil {
		t.Error("the VPN is gone after a no")
	}
}

// A VPN made protected between the question and the step is a new
// question: the step asks again, naming it.
func TestVpnRmChangedAsksAgain(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080", "--protected")
	mustRun(t, "vpn", "add", "lab2", "socks", "--proxy-address", "127.0.0.1:1081")
	texts := windowText(t, true)
	asked := inStepAsks(t)
	savedBefore := beforeLock
	t.Cleanup(func() { beforeLock = savedBefore })
	beforeLock = func() {
		beforeLock = func() {}
		if err := store.Update(store.Save(), func(s *store.State) error {
			s.Vpns["lab2"].Protected = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "vpn", "rm", "lab", "lab2", "--yes")
	if len(*texts) != 2 || strings.Contains((*texts)[0], "lab2") || !strings.Contains((*texts)[1], "lab2") {
		t.Errorf("windows %q: want one for lab, then one that names lab2", *texts)
	}
	if len(*asked) != 1 {
		t.Errorf("asked inside the step %d times, want once", len(*asked))
	}
}

// An ask inside a store step is in the command's audit record.
func TestAskInStoreStepIsAudited(t *testing.T) {
	groupOfFour(t)
	typesAnswers(t, "y\ny\n")
	inStepAsks(t)
	savedBefore := beforeLock
	t.Cleanup(func() { beforeLock = savedBefore })
	beforeLock = func() {
		beforeLock = func() {}
		_ = store.Update(store.Save(), func(s *store.State) error {
			s.Hosts["h5"] = &store.Host{Name: "h5", Address: "10.0.0.5", User: "u", Groups: []string{"g"}}
			return nil
		})
	}
	mustRun(t, "group", "rm", "g")
	rec := lastAudit(t)
	if rec["asked_in_store_step"] != true || rec["asked_in_store_step_command"] != "group.rm" {
		t.Errorf("audit record %v", rec)
	}
}
