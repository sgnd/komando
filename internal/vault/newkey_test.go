package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// keychainStandIn plays the system's secret-tool (Linux), never the real
// keychain. It keeps one key in a file and logs the first word of every
// call; with failStore, `store` fails, as on a server with no Secret
// Service. calls returns the log so far, one word per line.
func keychainStandIn(t *testing.T, failStore bool) (calls func() string) {
	t.Helper()
	dir := t.TempDir()
	savedOS, savedDirs := keychainOS, toolDirs
	keychainOS = "linux"
	toolDirs = []string{dir}
	t.Cleanup(func() { keychainOS, toolDirs = savedOS, savedDirs })
	fail := ""
	if failStore {
		fail = `echo "no Secret Service" >&2; exit 1;`
	}
	script := `#!/bin/sh
echo "$1" >> "` + dir + `/calls"
kept="` + dir + `/kept"
case "$1" in
  store) ` + fail + ` for a in "$@"; do [ ${#a} -ge 64 ] && { echo "a key in the arguments" >&2; exit 9; }; done; cat > "$kept" ;;
  lookup) [ -f "$kept" ] && cat "$kept" || exit 1 ;;
  clear) rm -f "$kept" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "") // TestMain turned the keychain off
	return func() string {
		b, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return strings.TrimSpace(string(b))
	}
}

// modeOnDisk is the mode vault.json names.
func modeOnDisk(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Mode
}

func noKeyFile(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Errorf("vault.key is on disk: %v", err)
	}
}

// A new vault without a passphrase keeps its key in the keychain, so a
// copy of the komando folder opens nothing.
func TestNewVaultKeyInKeychain(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keychain" {
		t.Fatalf("mode %q, want keychain", m)
	}
	noKeyFile(t)
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
	if s, err := Check(); err != nil || s.Mode != "keychain" {
		t.Errorf("Check: %+v %v", s, err)
	}
	// looked for a key, stored a new one, read it back, and later reads use it
	if got := calls(); !strings.HasPrefix(got, "lookup\nstore\nlookup") {
		t.Errorf("calls:\n%s", got)
	}
}

// Where the keychain cannot keep the key, the vault keeps it in vault.key,
// as before, and nothing is lost.
func TestNewVaultKeychainFails(t *testing.T) {
	freshHome(t)
	keychainStandIn(t, true)
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Fatalf("mode %q, want keyfile", m)
	}
	if _, err := os.Stat(store.Path("vault.key")); err != nil {
		t.Errorf("no vault.key: %v", err)
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
}

// A key already in the keychain under this folder's name belongs to a vault
// that was moved aside (a backup): the new vault uses it and never replaces
// it, so the old vault still opens.
func TestNewVaultKeepsKeychainKey(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	if err := Set("old", "kept value"); err != nil {
		t.Fatal(err)
	}
	aside := vaultPath() + ".aside"
	if err := os.Rename(vaultPath(), aside); err != nil {
		t.Fatal(err)
	}
	if err := Set("new", "v"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keychain" {
		t.Fatalf("mode %q, want keychain", m)
	}
	if n := strings.Count(calls(), "store"); n != 1 {
		t.Errorf("the key was stored %d times, want once:\n%s", n, calls())
	}
	if err := os.Rename(aside, vaultPath()); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("old"); err != nil || v != "kept value" {
		t.Errorf("the vault moved aside no longer opens: %q %v", v, err)
	}
}

// KOMANDO_KEYCHAIN=off (CI runners, containers, test runs): the keychain
// is never run, and the key goes into vault.key.
func TestNewVaultKeychainOff(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("mode %q, want keyfile", m)
	}
	if got := calls(); got != "" {
		t.Errorf("the keychain was run:\n%s", got)
	}
	if _, err := KeyToKeychain(); err == nil || !strings.Contains(err.Error(), "KOMANDO_KEYCHAIN=off") {
		t.Errorf("secret keychain with the keychain off: %v", err)
	}
}

// A vault that exists keeps its mode: one made with vault.key (and empty,
// its key not made yet) gets vault.key, and a passphrase vault stays one.
// Only `komando secret keychain` moves a key.
func TestExistingVaultKeepsMode(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	vf, _ := json.Marshal(map[string]any{"version": 1, "salt": []byte("0123456789abcdef"), "mode": "keyfile", "entries": map[string]any{}})
	if err := os.WriteFile(vaultPath(), vf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("an existing key-file vault became %q", m)
	}
	if got := calls(); got != "" {
		t.Errorf("the keychain was run for an existing vault:\n%s", got)
	}

	freshHome(t)
	t.Setenv("KOMANDO_VAULT_PASS", "a passphrase that is long enough")
	savedN := PassphraseN
	PassphraseN = 1 << 10 // quick; the cost is not what this test is about
	defer func() { PassphraseN = savedN }()
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "passphrase" {
		t.Errorf("a new vault with KOMANDO_VAULT_PASS is %q", m)
	}
	if got := calls(); got != "" {
		t.Errorf("the keychain was run for a passphrase vault:\n%s", got)
	}
}

// `komando secret keychain` on a vault with no secrets yet: its new key
// goes straight into the keychain, and vault.json says so.
func TestKeyToKeychainNewVault(t *testing.T) {
	freshHome(t)
	keychainStandIn(t, false)
	tool, err := KeyToKeychain()
	if err != nil || tool == "" {
		t.Fatalf("%q %v", tool, err)
	}
	if m := modeOnDisk(t); m != "keychain" {
		t.Errorf("mode %q, want keychain", m)
	}
	noKeyFile(t)
}
