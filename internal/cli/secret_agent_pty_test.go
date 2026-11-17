//go:build !windows

package cli

import (
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// An AI agent that runs komando under a terminal (a harness that gives its
// shell a pty) is never asked for a value: it gets NEEDS_PERSON at once,
// instead of a hidden prompt that waits for an answer nobody types.
func TestSecretSetAgentUnderPTYNeverAsks(t *testing.T) {
	invHome(t)
	m, tty, err := openPTY()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	defer m.Close()
	defer tty.Close()
	savedIn, savedErr := tcl.stdin, tcl.out.Err
	tcl.stdin, tcl.out.Err = tty, tty
	t.Cleanup(func() { tcl.stdin, tcl.out.Err = savedIn, savedErr })
	asAgent(t, true, true)

	type result struct {
		d map[string]any
		e *out.Error
	}
	run := func(args ...string) result {
		t.Helper()
		done := make(chan result, 1)
		go func() { d, e := invRun(t, args...); done <- result{d, e} }()
		select {
		case r := <-done:
			return r
		case <-time.After(5 * time.Second):
			_, _ = m.WriteString("typed-by-nobody\r") // let the prompt end, so the next test runs
			<-done
			t.Fatalf("%v: komando waits at a hidden prompt for an AI agent", args)
		}
		return result{}
	}
	if r := run("secret", "set", "web1-pass"); r.e == nil || r.e.Code != "NEEDS_PERSON" {
		t.Errorf("want NEEDS_PERSON, got %+v", r.e)
	}
	// a dry run is never blocked: it previews and names what the real run needs
	r := run("secret", "set", "web1-pass", "--dry-run")
	if r.e != nil || r.d["would_set"] != true || r.d["replaced"] != false {
		t.Fatalf("dry run: %v %+v", r.d, r.e)
	}
	if wb, _ := r.d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb["code"] != "NEEDS_PERSON" {
		t.Errorf("dry run would_be_blocked: %v", r.d["_meta"])
	}
	if names := secretNames(); len(names) != 0 {
		t.Errorf("the dry run stored %v", names)
	}
}
