//go:build linux || darwin

package engine

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The helper is this test binary run again with no environment at all.
func TestAncestorHelper(t *testing.T) {
	if len(os.Environ()) > 0 {
		t.Skip("run by TestAncestorAgentRealProcesses")
	}
	os.Stdout.WriteString("ancestor=" + ParentAgent() + "\n")
}

// A real process tree: an agent's shell holds the variable, a child with
// no environment under it asks who is above it.
func TestAncestorAgentRealProcesses(t *testing.T) {
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// "; true" keeps sh alive as the parent instead of replacing itself
	cmd := exec.Command("sh", "-c", `env -i "$0" -test.run=TestAncestorHelper -test.v; true`, bin)
	cmd.Env = []string{"CLAUDECODE=1", "PATH=" + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if !strings.Contains(string(b), "ancestor=Claude Code\n") {
		t.Errorf("a child with no environment under an agent's shell was not recognised: %s", b)
	}
}
