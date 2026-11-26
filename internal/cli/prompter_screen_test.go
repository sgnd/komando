package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/engine"
)

// The switch stays off until the v0.18.0 cut: a person sees no screen yet.
func TestInteractiveSwitchOff(t *testing.T) {
	if interactiveOn {
		t.Fatal("the interactive mode is on before the cut (C162)")
	}
}

// TestInteractiveGate: the screen starts only when every condition holds;
// any one that fails gives no screen. Agent detection counts a variable
// whatever its value, so an agent told to clear it still gets no screen.
func TestInteractiveGate(t *testing.T) {
	type in struct {
		on, terminal, stdout, agent bool
		ci, term, format            string
		args                        []string
	}
	ok := in{on: true, terminal: true, stdout: true, term: "xterm-256color", format: "text", args: []string{"host", "exec"}}
	if !screenGate(ok.on, ok.terminal, ok.stdout, ok.agent, ok.ci, ok.term, ok.format, ok.args) {
		t.Fatal("a person at a terminal with the switch on gets no screen")
	}
	for _, f := range []string{"", "auto", "text"} {
		if !screenGate(true, true, true, false, "", "xterm", f, nil) {
			t.Errorf("format %q gives no screen", f)
		}
	}
	tests := []struct {
		name string
		mod  func(*in)
	}{
		{"switch off", func(c *in) { c.on = false }},
		{"stdin or stderr not a terminal", func(c *in) { c.terminal = false }},
		{"stdout not a terminal (a pipe)", func(c *in) { c.stdout = false }},
		{"an AI agent", func(c *in) { c.agent = true }},
		{"CI=1", func(c *in) { c.ci = "1" }},
		{"CI=true", func(c *in) { c.ci = "true" }},
		{"TERM=dumb", func(c *in) { c.term = "dumb" }},
		{"-o json", func(c *in) { c.format = "json" }},
		{"-o yaml", func(c *in) { c.format = "yaml" }},
		{"--yes", func(c *in) { c.args = append(c.args, "--yes") }},
		{"--yes=true", func(c *in) { c.args = append(c.args, "--yes=true") }},
		{"--yes=false still a decision", func(c *in) { c.args = append(c.args, "--yes=false") }},
		{"-y", func(c *in) { c.args = append(c.args, "-y") }},
		{"-y in a group", func(c *in) { c.args = append(c.args, "-ny") }},
		{"--allow-dangerous", func(c *in) { c.args = append(c.args, "--allow-dangerous") }},
		{"--allow-dangerous=true", func(c *in) { c.args = append(c.args, "--allow-dangerous=true") }},
		{"--reveal", func(c *in) { c.args = append(c.args, "--reveal") }},
		{"--reveal=1", func(c *in) { c.args = append(c.args, "--reveal=1") }},
		{"flag before the command", func(c *in) { c.args = append([]string{"--yes"}, c.args...) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ok
			c.args = append([]string(nil), ok.args...)
			tt.mod(&c)
			if screenGate(c.on, c.terminal, c.stdout, c.agent, c.ci, c.term, c.format, c.args) {
				t.Errorf("%s: the screen would start", tt.name)
			}
		})
	}
	for _, ci := range []string{"", "0", "false"} {
		if !screenGate(true, true, true, false, ci, "xterm", "text", nil) {
			t.Errorf("CI=%q counts as CI", ci)
		}
	}
	// a flag-like word that is not an approval flag does not stop it
	for _, a := range []string{"--dry-run", "-o", "text", "--yesterday-is-not-yes"} {
		if carriesApproval([]string{a}) {
			t.Errorf("%q counts as an approval flag", a)
		}
	}
}

// Every agent variable, set to anything (also empty, 0 and false), makes
// the caller an agent, so the screen never starts for it.
func TestInteractiveGateAgentVars(t *testing.T) {
	for _, v := range engine.AgentVars() {
		for _, val := range []string{"", "0", "false", "1"} {
			lookup := func(k string) (string, bool) {
				if k == v {
					return val, true
				}
				return "", false
			}
			agent := engine.AgentName(lookup) != ""
			if !agent {
				t.Errorf("%s=%q is not an agent", v, val)
				continue
			}
			if screenGate(true, true, true, agent, "", "xterm", "text", nil) {
				t.Errorf("%s=%q gets the screen", v, val)
			}
		}
	}
}
