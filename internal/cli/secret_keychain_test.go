package cli

import (
	"bytes"
	"encoding/json"
	"os"
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

// keyfileHome is a komando home whose vault opens with vault.key, holding
// one secret. It returns vault.key's bytes. The vault keeps the passphrase
// an earlier test gave it, so the mode is written into vault.json first: a
// new vault takes its mode from there, not from KOMANDO_VAULT_PASS.
func keyfileHome(t *testing.T) []byte {
	t.Helper()
	invHome(t)
	vf, _ := json.Marshal(map[string]any{"version": 1, "salt": []byte("0123456789abcdef"), "mode": "keyfile", "entries": map[string]any{}})
	if err := os.WriteFile(store.Path("vault.json"), vf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vault.Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(store.Path("vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// keyStays: vault.key still holds key, and the vault still opens with it.
func keyStays(t *testing.T, key []byte) {
	t.Helper()
	if b, err := os.ReadFile(store.Path("vault.key")); err != nil || !bytes.Equal(b, key) {
		t.Errorf("vault.key changed: %v", err)
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
	if d = mustRun(t, "secret", "keychain", "--off", "--dry-run"); d["would"] != "move the vault key back into vault.key" {
		t.Errorf("--off dry run: %v", d)
	}
	keyStays(t, key)
}

// --off weakens where the key is kept, so it is a safety setting: --yes.
// With the key already in vault.key it changes nothing and says so.
func TestSecretKeychainOff(t *testing.T) {
	key := keyfileHome(t)
	if e := wantCode(t, "SAFETY_SETTING", "secret", "keychain", "--off"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	if d := mustRun(t, "secret", "keychain", "--off", "--yes"); d["key"] != "vault.key" {
		t.Errorf("--off --yes: %v", d)
	}
	keyStays(t, key)
}

// A vault opened with KOMANDO_VAULT_PASS has no key to move: refused, on
// every system, before any keychain is written.
func TestSecretKeychainPassphraseVault(t *testing.T) {
	invHome(t)
	setSecret(t, "db-pass", "s3cret")
	e := wantCode(t, "KEYCHAIN_FAILED", "secret", "keychain")
	if e.Exit != out.ExitRemote {
		t.Errorf("exit %d", e.Exit)
	}
	if v, err := vault.Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("vault no longer opens: %q %v", v, err)
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Errorf("a key file appeared: %v", err)
	}
}

// Where no keychain tool is installed (a Linux server or CI runner without
// secret-tool), the move fails cleanly and the key stays in vault.key.
func TestSecretKeychainNoTool(t *testing.T) {
	if _, err := vault.KeychainTool(); err == nil {
		t.Skip("a keychain tool is installed here; this test must not write to it")
	}
	key := keyfileHome(t)
	e := wantCode(t, "KEYCHAIN_FAILED", "secret", "keychain")
	if e.Exit != out.ExitRemote || e.Hint != "the vault still uses vault.key; fix the keychain and try again" {
		t.Errorf("error: %+v", e)
	}
	keyStays(t, key)
}
