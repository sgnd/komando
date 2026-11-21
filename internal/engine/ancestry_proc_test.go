//go:build linux || darwin

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The helper is this test binary run again with no environment at all.
func TestAncestorHelper(t *testing.T) {
	if len(os.Environ()) > 0 {
		t.Skip("run by TestAncestorAgentRealProcesses")
	}
	// only the shell directly above counts: the processes above the test
	// run (maybe an agent's) must not decide the answer
	parent := os.Getppid()
	os.Stdout.WriteString("ancestor=" + AncestorAgent(oneLevel{osProcs(), parent}, parent) + "\n")
}

// oneLevel shows the process table down to one process and no further up.
type oneLevel struct {
	ProcTable
	only int
}

func (o oneLevel) Proc(pid int) (Proc, bool) {
	p, ok := o.ProcTable.Proc(pid)
	if !ok || pid != o.only {
		return Proc{}, false
	}
	p.PPID = 0
	return p, true
}

// The parent helper holds the agent variable (the test binary is not an
// Apple program, so its environment is readable) and runs the child with
// no environment.
func TestAncestorParent(t *testing.T) {
	if os.Getenv("KOMANDO_ANCESTOR_PARENT") == "" {
		t.Skip("run by TestAncestorAgentRealProcesses")
	}
	bin, _ := os.Executable()
	b, err := exec.Command("env", "-i", bin, "-test.run=TestAncestorHelper", "-test.v").CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	os.Stdout.Write(b)
}

// A real process tree: a parent that holds the variable, a child with no
// environment under it asking who is above it.
func TestAncestorAgentRealProcesses(t *testing.T) {
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-test.run=TestAncestorParent", "-test.v")
	cmd.Env = []string{"CLAUDECODE=1", "KOMANDO_ANCESTOR_PARENT=1", "PATH=" + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if !strings.Contains(string(b), "ancestor=Claude Code\n") {
		t.Errorf("a child with no environment under an agent's process was not recognised: %s", b)
	}
}

// A node-style harness keeps its variables in memory, so its shell can run
// `exec env -i komando`: only the harness's argv names it.
func TestAncestorAgentByArgv(t *testing.T) {
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "claude-code")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "cli.js")
	script := "#!/bin/sh\nenv -i \"$1\" -test.run=TestAncestorHelper -test.v\ntrue\n"
	if err := os.WriteFile(cli, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// sh runs cli.js: sh's argv[1] is its path and its environment is empty
	cmd := exec.Command("sh", cli, bin)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if !strings.Contains(string(b), "ancestor=Claude Code\n") {
		t.Errorf("a harness known only by its argv was not recognised: %s", b)
	}
}
