package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// agentAbove makes the processes above the test an AI agent's, with the
// test's own environment clean: the case of a program that stripped its
// variables.
func agentAbove(t *testing.T) {
	t.Helper()
	saved := ancestorAgent
	t.Cleanup(func() { ancestorAgent = saved; resetApproval() })
	ancestorAgent = func() string { return "Claude Code" }
	resetApproval()
}

// A caller with no agent variables but an agent above it is an agent: it
// is not a person at a terminal.
func TestStrippedAgentIsNotAPerson(t *testing.T) {
	shellTerminal(t, "", true)
	agentAbove(t)
	if !tcl.isAgent() || tcl.caller().Agent != "Claude Code" {
		t.Fatalf("caller %+v", tcl.caller())
	}
	if tcl.interactive() {
		t.Fatal("an agent's stripped call is interactive")
	}
	if err := runShell(tcl, context.Background(), "web"); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
		t.Errorf("shell: %v, want NEEDS_TERMINAL", err)
	}
}

// The gate refuses it as well, whatever variables it set.
func TestSSHGateStrippedAgentCaller(t *testing.T) {
	gateSessionLab(t)
	shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
		t.Error("it connected")
		return nil
	}
	shellTerminal(t, "/dev/pts/3", true)
	agentAbove(t)
	ran, _, e := gateRun(t, "komando host ssh shell web", "--name", "ops", "--shell-access")
	if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "AI agent") {
		t.Fatalf("ran %q, error %+v; want SSH_GATE_REFUSED for an AI agent", ran, e)
	}
}

// The program's own call asks the process tree; a test can stand in for it.
func TestProcessCallAsksAncestors(t *testing.T) {
	agentAbove(t)
	if got := processCall().Caller(); !got.IsAgent() {
		t.Errorf("processCall ignores the process tree: %+v", got)
	}
}
