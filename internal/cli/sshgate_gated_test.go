package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/engine"
)

// TestGated: a call is the gate's when its agent name starts with
// "ssh-gate key ", the label sshgate.go gives the key's command. Nothing
// else is: not a person, not another agent, not a near spelling.
func TestGated(t *testing.T) {
	tests := []struct {
		name  string
		kind  engine.Kind
		agent string
		want  bool
	}{
		{"a gate key", engine.Agent, "ssh-gate key phone-read", true},
		{"the prefix alone", engine.Agent, "ssh-gate key ", true},
		{"no space after key", engine.Agent, "ssh-gate key", false},
		{"another agent", engine.Agent, "claude", false},
		{"no agent name", engine.Agent, "", false},
		{"a prefix before the label", engine.Agent, "x ssh-gate key phone", false},
		{"a different case", engine.Agent, "SSH-GATE KEY phone", false},
		{"a person", engine.Person, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := testCall()
			setTestCaller(cl, engine.Caller{Kind: tt.kind, Agent: tt.agent})
			if got := cl.gated(); got != tt.want {
				t.Errorf("gated() with agent %q = %v, want %v", tt.agent, got, tt.want)
			}
		})
	}
}
