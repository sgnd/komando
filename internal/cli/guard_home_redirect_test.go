package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// accountHomeAt makes dir the account's home folder in the user database
// for the rest of the test, and HOME too, with no KOMANDO_HOME: komando
// keeps its data in dir/.komando.
func accountHomeAt(t *testing.T, dir string) {
	t.Helper()
	saved := store.AccountHome
	store.AccountHome = func() (string, error) { return dir, nil }
	t.Cleanup(func() { store.AccountHome = saved })
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("KOMANDO_HOME", "")
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	closeStoreAtEnd(t)
}

// An AI agent's HOME=/tmp/x does not move komando's data: komando takes an
// agent's home folder from the user database, so the person's protected
// server stays protected, and the audit log is the person's.
func TestAgentHomeRedirect(t *testing.T) {
	real, fake := t.TempDir(), t.TempDir()
	accountHomeAt(t, real)
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--protected") // the person
	store.Close()

	texts := windowText(t, false)
	t.Setenv("HOME", fake)
	t.Setenv("USERPROFILE", fake)
	if d := mustRun(t, "list"); d["count"] != float64(1) {
		t.Fatalf("an agent with HOME=%s sees the person's servers: %v", fake, d)
	}
	wantCode(t, "PROTECTED_HOST", "exec", "web2", "--", "touch", "/tmp/x")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	if _, err := os.Lstat(filepath.Join(fake, ".komando")); !os.IsNotExist(err) {
		t.Errorf("komando made a data folder in the agent's HOME: %v", err)
	}

	// the person, in the usual home, finds the agent's blocked try
	noAgent(t)
	t.Setenv("HOME", real)
	t.Setenv("USERPROFILE", real)
	d := mustRun(t, "audit", "--failed", "-n", "0")
	found := false
	for _, e := range d["entries"].([]any) {
		m := e.(map[string]any)
		if m["command"] == "exec" && m["blocked"] == "PROTECTED_HOST" && m["agent"] != nil {
			found = true
		}
	}
	if !found {
		t.Errorf("the agent's blocked exec is in the person's audit log: %v", d["entries"])
	}
}

// A person may set HOME: komando follows it.
func TestPersonHomeFollowsHOME(t *testing.T) {
	real, other := t.TempDir(), t.TempDir()
	accountHomeAt(t, real)
	t.Setenv("HOME", other)
	t.Setenv("USERPROFILE", other)
	if got, want := store.Home(), filepath.Join(other, ".komando"); got != want {
		t.Errorf("a person's store.Home() = %s, want %s", got, want)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	if got, want := store.Home(), filepath.Join(real, ".komando"); got != want {
		t.Errorf("an agent's store.Home() = %s, want %s", got, want)
	}
}

// The agent guard protects the account's ~/.komando and ~/.ssh also when
// the agent's HOME is another folder.
func TestGuardProtectsAccountHome(t *testing.T) {
	real, fake := t.TempDir(), t.TempDir()
	accountHomeAt(t, real)
	setCallerEnv(t, "CLAUDECODE", "1")
	t.Setenv("HOME", fake)
	t.Setenv("USERPROFILE", fake)
	for _, p := range []string{filepath.Join(real, ".komando", "store.db"), filepath.Join(real, ".ssh", "id_ed25519")} {
		if localSecret(tcl, p) == "" {
			t.Errorf("%s is not a secret with HOME=%s", p, fake)
		}
	}
}

// With no account in the user database (nor getent), komando cannot check
// HOME: an AI agent's command needs a person's yes.
func TestAgentHomeUnknownStops(t *testing.T) {
	home := t.TempDir()
	accountHomeAt(t, home)
	mustRun(t, "host", "add", "web1", "u@10.0.0.9") // the person
	store.AccountHome = func() (string, error) { return "", errors.New("no entry for uid 4242") }
	texts := windowText(t, false)
	if e := wantCode(t, "SAFETY_SETTING", "list"); !strings.Contains(e.Message, "cannot find this account's home folder") {
		t.Errorf("message: %s", e.Message)
	}
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	noAgent(t)
	mustRun(t, "list") // a person is not asked
}

// The e2e lab's agent (test/e2e/lib.sh): KOMANDO_HOME is the run's folder
// and HOME a folder whose .komando is a link to it, neither the account's
// home. KOMANDO_HOME names ~/.komando of that HOME, so nothing stops.
func TestAgentLabHome(t *testing.T) {
	unixOnly(t, "symbolic links")
	account, run, agentHome := t.TempDir(), t.TempDir(), t.TempDir()
	accountHomeAt(t, account)
	saved := defaultHome
	defaultHome = func() string { return filepath.Join(account, ".komando") } // the real rule
	t.Cleanup(func() { defaultHome = saved })
	t.Setenv("KOMANDO_HOME", run)
	mustRun(t, "host", "add", "web1", "u@10.0.0.9")
	if err := os.Symlink(run, filepath.Join(agentHome, ".komando")); err != nil {
		t.Fatal(err)
	}
	windowText(t, false)
	t.Setenv("HOME", agentHome)
	if d := mustRun(t, "list"); d["count"] != float64(1) {
		t.Fatalf("list: %v", d)
	}
	// KOMANDO_HOME that is no ~/.komando at all still needs a person
	t.Setenv("HOME", t.TempDir())
	wantCode(t, "SAFETY_SETTING", "list")
}
