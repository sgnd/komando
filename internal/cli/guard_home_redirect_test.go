package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
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

// An AI agent that sets both HOME=/x and KOMANDO_HOME=/x/.komando in front
// of komando moves the data folder just as KOMANDO_HOME alone does: it
// needs a person's yes. Only ~/.komando of the account's home (or a link
// to the same folder) is the usual one.
func TestAgentHomePairStops(t *testing.T) {
	account, fake := t.TempDir(), t.TempDir()
	accountHomeAt(t, account)
	saved := defaultHome
	defaultHome = func() string { return filepath.Join(account, ".komando") } // the real rule
	t.Cleanup(func() { defaultHome = saved })
	mustRun(t, "host", "add", "web2", "u@10.0.0.2", "--protected") // the person
	store.Close()

	texts := windowText(t, false)
	if err := os.Mkdir(filepath.Join(fake, ".komando"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", fake)
	t.Setenv("USERPROFILE", fake)
	t.Setenv("KOMANDO_HOME", filepath.Join(fake, ".komando"))
	wantCode(t, "NEEDS_PERSON", "list")
	wantCode(t, "NEEDS_PERSON", "exec", "web2", "--", "touch", "/tmp/x")
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
	if _, err := os.Lstat(filepath.Join(fake, ".komando", "store.db")); !os.IsNotExist(err) {
		t.Errorf("komando made a store in the agent's folder: %v", err)
	}

	// KOMANDO_HOME that names the account's ~/.komando is the usual folder,
	// also through a link, whatever HOME says
	t.Setenv("KOMANDO_HOME", filepath.Join(account, ".komando"))
	if d := mustRun(t, "list"); d["count"] != float64(1) {
		t.Fatalf("list: %v", d)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "k")
		if err := os.Symlink(filepath.Join(account, ".komando"), link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KOMANDO_HOME", link)
		if d := mustRun(t, "list"); d["count"] != float64(1) {
			t.Fatalf("list through a link: %v", d)
		}
		// from the check on komando uses the account's folder by its own
		// path: a link repointed after the check leads nowhere
		if got, want := os.Getenv("KOMANDO_HOME"), filepath.Join(account, ".komando"); got != want {
			t.Errorf("after the check KOMANDO_HOME = %s, want %s", got, want)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fake, link); err != nil {
			t.Fatal(err)
		}
		if got := store.Home(); got != filepath.Join(account, ".komando") {
			t.Errorf("the repointed link moved komando's data to %s", got)
		}
	}
}

// The stop for an agent's other data folder is final all the way out:
// the hint names no flag, no window opens (--reveal asked before the
// check once), nothing is made or written in that folder, and the
// unknown-account case does not offer a window for it either.
func TestAgentOtherHomeIsFinal(t *testing.T) {
	account, other := t.TempDir(), t.TempDir()
	accountHomeAt(t, account)
	saved := defaultHome
	defaultHome = func() string { return filepath.Join(account, ".komando") } // the real rule
	t.Cleanup(func() { defaultHome = saved })
	mustRun(t, "host", "add", "web1", "u@10.0.0.9") // the person, in the usual folder
	store.Close()

	texts := windowText(t, true)
	t.Setenv("KOMANDO_HOME", other)
	for _, args := range [][]string{{"list"}, {"list", "--yes"}, {"list", "--dry-run"}, {"list", "--reveal"}, {"guide", "uninstall", "--yes"}} {
		code, text := runMain(t, args...)
		if code != out.ExitPolicy || !strings.Contains(text, `"code":"NEEDS_PERSON"`) {
			t.Errorf("%v: exit %d %s", args, code, text)
			continue
		}
		var env struct {
			Error struct{ Hint string } `json:"error"`
		}
		if err := json.Unmarshal([]byte(text), &env); err != nil {
			t.Fatalf("%v: %v in %s", args, err, text)
		}
		h := env.Error.Hint
		if strings.Contains(h, "--yes") || strings.Contains(h, "window") || !strings.Contains(h, "KOMANDO_HOME") || strings.Contains(h, "a link") {
			t.Errorf("%v: hint %q", args, h)
		}
	}
	if len(*texts) != 0 {
		t.Errorf("a window opened for another data folder: %q", *texts)
	}
	if left, _ := os.ReadDir(other); len(left) != 0 {
		t.Errorf("komando made %d files in the other folder (%s ...)", len(left), left[0].Name())
	}

	// an account the user database does not know: another KOMANDO_HOME is
	// still another folder, and stops without a window
	store.AccountHome = func() (string, error) { return "", errors.New("no entry for uid 4242") }
	if code, text := runMain(t, "list", "--yes"); code != out.ExitPolicy || !strings.Contains(text, "KOMANDO_HOME points komando at") {
		t.Errorf("unknown account: exit %d %s", code, text)
	}
	if len(*texts) != 0 {
		t.Errorf("unknown account: a window opened: %q", *texts)
	}
}
