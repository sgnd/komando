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
func TestSwarmApplyNotJudgedAsExec(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "swarm1", "deploy@"+closedAddr(t))
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
	// the stack name is a name: words docker would read as flags are refused
	for _, stack := range []string{"--prune", "-c/etc/x.yml", "a b", ""} {
		if _, e := invRun(t, "cluster", "apply", "swarm1", "--file", plain, "--stack", stack); e == nil || e.Code != "USAGE" {
			t.Errorf("--stack %q: want USAGE, got %+v", stack, e)
		}
	}
}

// A Swarm service or stack NAME reaches docker as a word of its own, and
// quoting keeps the shell from splitting it but not docker from reading a
// leading dash as a flag. Every Swarm entry refuses such a name first.
func TestSwarmEntryNames(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "swarm1", "deploy@"+closedAddr(t))
	for _, args := range [][]string{
		{"cluster", "rm", "swarm1", "service/--help"},
		{"cluster", "rm", "swarm1", "stack/--help"},
		{"cluster", "scale", "swarm1", "service/--help", "2"},
		{"cluster", "restart", "swarm1", "service/--help"},
		{"cluster", "rollback", "swarm1", "service/--help"},
		{"cluster", "deploy", "swarm1", "service/--help", "--image", "nginx:1.27"},
	} {
		if _, e := invRun(t, args...); e == nil || e.Code != "USAGE" {
			t.Errorf("%v: want USAGE, got %+v", args, e)
		}
	}
}
