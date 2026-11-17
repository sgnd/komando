package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// Lending a server your ssh-agent needs a yes (a person's, for an AI
// agent); taking it back does not.
func TestHostEditForwardAgent(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "jump1", "ops@10.0.0.9")
	if e := wantCode(t, "SAFETY_SETTING", "host", "edit", "jump1", "--forward-agent"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	if st := mustState(t); st.Hosts["jump1"].ForwardAgent {
		t.Fatal("set without a yes")
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "SAFETY_SETTING", "host", "edit", "jump1", "--forward-agent")
	mustRun(t, "host", "edit", "jump1", "--forward-agent=false")
	mustRun(t, "host", "edit", "jump1", "--unset", "forward-agent")
	if d := mustRun(t, "--dry-run", "host", "edit", "jump1", "--forward-agent"); d == nil {
		t.Error("a dry run is never blocked")
	}
}
