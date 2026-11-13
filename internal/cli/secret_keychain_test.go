package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `secret keychain` is not in the e2e (test/e2e/checks/coverage.sh says
// why): a real run writes to the OS keychain. These are the paths that never
// reach a keychain write, so they run anywhere, a Mac included, without
// touching the login keychain. The round trip itself is in
// internal/vault/keychain_test.go.

// keyfileHome is a komando home whose store opens with store.key, holding
// one secret. It returns the key file's bytes.
func keyfileHome(t *testing.T) []byte {
	t.Helper()
	invHome(t)
	t.Setenv("KOMANDO_VAULT_PASS", "")
	vault.ReadPassStdin(strings.NewReader("")) // forget one read earlier
	if err := vault.Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(store.Path("store.key"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// atTerminal makes the test run as a person at a terminal.
func atTerminal(t *testing.T) {
	t.Helper()
	saved := tcl.terminal
	tcl.terminal = true
	t.Cleanup(func() { tcl.terminal = saved })
}

// keyStays: store.key still holds key, and the vault still opens with it.
func keyStays(t *testing.T, key []byte) {
	t.Helper()
	if b, err := os.ReadFile(store.Path("store.key")); err != nil || !bytes.Equal(b, key) {
		t.Errorf("store.key changed: %v", err)
	}
	if v, err := vault.Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("vault no longer opens: %q %v", v, err)
	}
}

func TestSecretKeychainDryRun(t *testing.T) {
	key := keyfileHome(t)
	tool, toolErr := vault.KeychainTool()
	d := mustRun(t, "secret", "keychain", "--dry-run")
	if d["dry_run"] != true || d["would"] != "move the vault key into the keychain" {
		t.Errorf("dry run: %v", d)
	}
	// it names the tool, or why there is none: the same answer as the real run
	if toolErr != nil {
		if d["problem"] != toolErr.Error() || d["keychain"] != nil {
			t.Errorf("no keychain tool here (%v), dry run says %v", toolErr, d)
		}
	} else if d["keychain"] != tool || d["problem"] != nil {
		t.Errorf("keychain %q here, dry run says %v", tool, d)
	}
	if d = mustRun(t, "secret", "keychain", "--off", "--dry-run"); d["would"] != "move the vault key back into store.key" {
		t.Errorf("--off dry run: %v", d)
	}
	keyStays(t, key)
}

// --off weakens where the key is kept, so it is a safety setting: --yes.
// With the key already in store.key it changes nothing and says so.
func TestSecretKeychainOff(t *testing.T) {
	key := keyfileHome(t)
	if e := wantCode(t, "SAFETY_SETTING", "secret", "keychain", "--off"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	if d := mustRun(t, "secret", "keychain", "--off", "--yes"); d["key"] != "store.key" {
		t.Errorf("--off --yes: %v", d)
	}
	keyStays(t, key)
}

// A vault opened with KOMANDO_VAULT_PASS has no key to move: refused, on
// every system, before any keychain is written.
func TestSecretKeychainPassphraseVault(t *testing.T) {
	invHome(t)
	atTerminal(t)
	setSecret(t, "db-pass", "s3cret")
	e := wantCode(t, "KEYCHAIN_FAILED", "secret", "keychain")
	if e.Exit != out.ExitRemote {
		t.Errorf("exit %d", e.Exit)
	}
	if v, err := vault.Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("vault no longer opens: %q %v", v, err)
	}
	if _, err := os.Stat(store.Path("store.key")); !os.IsNotExist(err) {
		t.Errorf("a key file appeared: %v", err)
	}
}

// Where no keychain tool is installed (a Linux server or CI runner without
// secret-tool), the move fails cleanly and the key stays in store.key.
func TestSecretKeychainNoTool(t *testing.T) {
	if _, err := vault.KeychainTool(); err == nil {
		t.Skip("a keychain tool is installed here; this test must not write to it")
	}
	key := keyfileHome(t)
	atTerminal(t)
	e := wantCode(t, "KEYCHAIN_FAILED", "secret", "keychain")
	if e.Exit != out.ExitRemote || !strings.HasSuffix(e.Message, "; the store still uses store.key, nothing was lost") || e.Hint != "a person unlocks the keychain (an AI agent asks the user), then run it again; on Linux it needs secret-tool and a keyring" {
		t.Errorf("error: %+v", e)
	}
	keyStays(t, key)
}

// Moving the key in may wait for an unlock prompt: an AI agent or a script
// gets NEEDS_PERSON at once, before any keychain is asked. The dry run says
// so instead of stopping.
func TestSecretKeychainNeedsPerson(t *testing.T) {
	key := keyfileHome(t)
	for _, agent := range []bool{false, true} {
		if agent {
			atTerminal(t) // an agent never counts as a person, terminal or not
			setCallerEnv(t, "KOMANDO_AGENT", "1")
		}
		e := wantCode(t, "NEEDS_PERSON", "secret", "keychain")
		if e.Exit != out.ExitPolicy || !strings.Contains(e.Hint, "own terminal") {
			t.Errorf("agent %v: %+v", agent, e)
		}
		d := mustRun(t, "secret", "keychain", "--dry-run")
		if b, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); b["code"] != "NEEDS_PERSON" {
			t.Errorf("agent %v: dry run: %v", agent, d)
		}
	}
	keyStays(t, key)
}
