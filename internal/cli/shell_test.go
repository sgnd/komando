package cli

import (
	"context"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// shellLab is a person at a terminal with one host; "x y" as the --via hop
// fails before any network, so a test that gets past the checks stops there.
func shellLab(t *testing.T, protected bool) {
	t.Helper()
	setHome(t, t.TempDir())
	saved, savedG := tcl.terminal, saveFlags(tcl)
	t.Cleanup(func() { tcl.terminal = saved; savedG.restore(); resetApproval(); tcl.out.Reset() })
	tcl.terminal = true
	// runShell runs no command (newRoot): what an earlier test's command
	// recorded (a would-be stop) is forgotten here
	tcl.out.Reset()
	err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["web1"] = &store.Host{Name: "web1", Address: "10.255.255.1", User: "deploy", Via: "x y", Protected: protected}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestShellNeedsTerminal(t *testing.T) {
	saved := tcl.terminal
	defer func() { tcl.terminal = saved }()
	tcl.terminal = false
	if err := runShell(tcl, context.Background(), "web1"); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
		t.Errorf("want NEEDS_TERMINAL, got %v", err)
	}
}

func TestShellDryRunContactsNothing(t *testing.T) {
	shellLab(t, false)
	setGate(tcl, true, gateDryRun)
	if err := runShell(tcl, context.Background(), "web1"); err != nil {
		t.Fatalf("dry run tried to connect: %v", err)
	}
}

func TestShellProtectedHost(t *testing.T) {
	shellLab(t, true)

	// dry run: shows the stop instead of hitting it
	setGate(tcl, true, gateDryRun)
	if err := runShell(tcl, context.Background(), "web1"); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if b := tcl.out.Blocked(); b == nil || b.Code != "PROTECTED_TARGET" {
		t.Errorf("dry run should report the protected stop, got %+v", b)
	}
	setGate(tcl, false, gateDryRun)

	// the person answers no
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedIn := tcl.stdin
	defer func() { tcl.stdin = savedIn }()
	tcl.stdin = r
	w.WriteString("n\n")
	w.Close()
	if err := runShell(tcl, context.Background(), "web1"); err == nil || toErr(err).Code != "PROTECTED_TARGET" {
		t.Errorf("no at the prompt: want PROTECTED_TARGET, got %v", err)
	}

	// --yes: past the check, it stops at the bad --via hop instead
	setGate(tcl, true, gateYes)
	if err := runShell(tcl, context.Background(), "web1"); err == nil || toErr(err).Code == "PROTECTED_TARGET" {
		t.Errorf("--yes: want a connect error, got %v", err)
	}
}
