package cli

import (
	"context"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// shellLab is a person at a terminal with one host; "x y" as the --via hop
// fails before any network, so a test that gets past the checks stops there.
func shellLab(t *testing.T, protected bool) {
	t.Helper()
	setHome(t, t.TempDir())
	saved, savedG := interactive, g
	t.Cleanup(func() { interactive, g = saved, savedG; resetApproval(); out.P.Reset() })
	interactive = func() bool { return true }
	err := store.Update(func(st *store.State) error {
		st.Hosts["web1"] = &store.Host{Name: "web1", Address: "10.255.255.1", User: "deploy", Via: "x y", Protected: protected}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestShellNeedsTerminal(t *testing.T) {
	saved := interactive
	defer func() { interactive = saved }()
	interactive = func() bool { return false }
	if err := runShell(context.Background(), "web1"); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
		t.Errorf("want NEEDS_TERMINAL, got %v", err)
	}
}

func TestShellDryRunContactsNothing(t *testing.T) {
	shellLab(t, false)
	g.dryRun = true
	if err := runShell(context.Background(), "web1"); err != nil {
		t.Fatalf("dry run tried to connect: %v", err)
	}
}

func TestShellProtectedHost(t *testing.T) {
	shellLab(t, true)

	// dry run: shows the stop instead of hitting it
	g.dryRun = true
	if err := runShell(context.Background(), "web1"); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if b := out.P.Blocked(); b == nil || b.Code != "PROTECTED_HOST" {
		t.Errorf("dry run should report the protected stop, got %+v", b)
	}
	g.dryRun = false

	// the person answers no
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedIn := os.Stdin
	defer func() { os.Stdin = savedIn }()
	os.Stdin = r
	w.WriteString("n\n")
	w.Close()
	if err := runShell(context.Background(), "web1"); err == nil || toErr(err).Code != "PROTECTED_HOST" {
		t.Errorf("no at the prompt: want PROTECTED_HOST, got %v", err)
	}

	// --yes: past the check, it stops at the bad --via hop instead
	g.yes = true
	if err := runShell(context.Background(), "web1"); err == nil || toErr(err).Code == "PROTECTED_HOST" {
		t.Errorf("--yes: want a connect error, got %v", err)
	}
}
