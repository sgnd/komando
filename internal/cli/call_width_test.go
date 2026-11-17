package cli

import (
	"bytes"
	"io"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
)

// A call's lines wrap at the width of its own writers, never the
// process's terminal: an app's writer is no terminal, so nothing wraps;
// stderr notes ask the call's stderr, a text result its stdout; an AI
// agent's never wrap.
func TestWidthIsTheCalls(t *testing.T) {
	var o, e bytes.Buffer
	person := newCall(engine.Call{Program: "komando", Stdout: &o, Stderr: &e, Terminal: true,
		LookupEnv: func(k string) (string, bool) { return map[string]string{"USER": "ana"}[k], k == "USER" }}, nil)
	if person.width() != 0 || textWidth(person) != 0 {
		t.Fatalf("an app's writers wrap: stderr %d, stdout %d", person.width(), textWidth(person))
	}

	saved := out.WidthOf
	t.Cleanup(func() { out.WidthOf = saved })
	out.WidthOf = func(w io.Writer) int { // a terminal on stderr only, 60 wide
		if w == io.Writer(&e) {
			return 60
		}
		return 0
	}
	if person.width() != 60 || textWidth(person) != 0 {
		t.Errorf("stderr a terminal, stdout a pipe: stderr %d, stdout %d", person.width(), textWidth(person))
	}
	agent := newCall(engine.Call{Program: "komando", Stdout: &o, Stderr: &e,
		LookupEnv: func(k string) (string, bool) { return "1", k == "CLAUDECODE" }}, nil)
	if agent.width() != 0 || textWidth(agent) != 0 {
		t.Errorf("an agent's lines wrap: stderr %d, stdout %d", agent.width(), textWidth(agent))
	}
}
