package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cluster apply on Swarm sends the stack file over standard input. The
// command judges the file it read (composeEscapes), so its own line is
// not stopped as exec text that hides a compose file; a file that hands
// a service the server still stops.
func TestSwarmApplyJudgesTheFileNotItsOwnLine(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "swarm1", "deploy@"+closedAddr(t))
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.yml")
	os.WriteFile(plain, []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o600)
	_, e := invRun(t, "cluster", "apply", "swarm1", "--file", plain, "--stack", "e2e")
	if e == nil || e.Code == "POLICY_BLOCKED" {
		t.Errorf("plain stack file: want the connection error, got %+v", e)
	}
	escape := filepath.Join(dir, "escape.yml")
	os.WriteFile(escape, []byte("services:\n  web:\n    image: nginx:1.27\n    volumes: [\"/:/host\"]\n"), 0o600)
	_, e = invRun(t, "cluster", "apply", "swarm1", "--file", escape, "--stack", "e2e")
	if e == nil || e.Code != "POLICY_BLOCKED" || !strings.Contains(e.Message, "stack file") {
		t.Errorf("stack file that binds /: want POLICY_BLOCKED on the stack file, got %+v", e)
	}
}
