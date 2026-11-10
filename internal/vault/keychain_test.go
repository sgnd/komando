package vault

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// TestMain keeps every test away from the real keychain: a new vault
// would otherwise put its key in the login keychain of whoever runs them.
// The tests that use a keychain set KOMANDO_KEYCHAIN themselves.
func TestMain(m *testing.M) {
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1")
	os.Exit(m.Run())
}

func freshHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "")
	os.Unsetenv("KOMANDO_VAULT_PASS")
	passMu.Lock()
	pass = ""
	passMu.Unlock()
	aeadMu.Lock()
	aeadCache = map[string]cipher.AEAD{}
	aeadMu.Unlock()
}

// roundTrip starts with the key in vault.key, then uses the keychain kc
// names ("" for the default one, a stand-in in these tests).
func roundTrip(t *testing.T, kc string) {
	t.Helper()
	t.Setenv("KOMANDO_KEYCHAIN", "off") // the vault starts with vault.key
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", kc)
	if _, err := KeyToKeychain(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Error("vault.key is still on disk")
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Fatalf("read with the key in the keychain: %q %v", v, err)
	}
	if err := Set("api", "tok"); err != nil {
		t.Fatal(err)
	}
	if err := KeyToFile(); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"db-pass": "s3cret", "api": "tok"} {
		if v, err := Get(k); err != nil || v != want {
			t.Errorf("%s back in a key file: %q %v", k, v, err)
		}
	}
	if _, err := keychainGet(); err == nil {
		t.Error("the key stayed in the keychain")
	}
}

// The Linux path with a stand-in secret-tool that keeps one secret in a
// file: the key must come in on stdin, never as an argument.
func TestKeychainSecretTool(t *testing.T) {
	freshHome(t)
	dir := t.TempDir()
	saved := keychainOS
	keychainOS = "linux"
	defer func() { keychainOS = saved }()
	script := `#!/bin/sh
kept="` + dir + `/kept"
case "$1" in
  store) for a in "$@"; do [ ${#a} -ge 64 ] && { echo "a key in the arguments" >&2; exit 9; }; done; cat > "$kept" ;;
  lookup) [ -f "$kept" ] && cat "$kept" || exit 1 ;;
  search) if [ -f "$kept" ]; then printf '[/org/freedesktop/secrets/collection/login/1]\nlabel = %s\n' "$4"; fi ;;
  clear) rm -f "$kept" ;;
esac
`
	os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755)
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	savedDirs := toolDirs
	toolDirs = []string{dir} // the stand-in plays the system's secret-tool
	defer func() { toolDirs = savedDirs }()
	roundTrip(t, "")
}

// A secret-tool or security found through PATH is never run: it would be
// handed the vault key, or could hand komando a key of its choosing.
func TestKeychainToolsNotFromPath(t *testing.T) {
	freshHome(t)
	t.Setenv("KOMANDO_KEYCHAIN", "")
	dir := t.TempDir()
	for _, name := range []string{"secret-tool", "security"} {
		os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\necho fake > "+filepath.Join(dir, "ran")+"\n"), 0o755)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	savedOS, savedDirs, savedSec := keychainOS, toolDirs, securityTool
	defer func() { keychainOS, toolDirs, securityTool = savedOS, savedDirs, savedSec }()
	toolDirs = []string{t.TempDir()} // no secret-tool in the system folders
	keychainOS = "linux"
	if _, err := KeychainTool(); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("linux without a system secret-tool: %v", err)
	}
	if _, err := keychainGet(); err == nil {
		t.Error("keychainGet found a key")
	}
	keychainOS, securityTool = "darwin", filepath.Join(t.TempDir(), "security")
	if _, err := KeychainTool(); err == nil {
		t.Error("macOS without its security tool")
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Fatal("a tool from PATH was run")
	}
	if got := keychainCmd("x").Path; got != securityTool {
		t.Errorf("macOS runs %s, want %s", got, securityTool)
	}
}

// The macOS path against a throwaway keychain file (never the login
// keychain). Opt in: it adds that file to the keychain list for a moment.
func TestKeychainMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("KOMANDO_TEST_KEYCHAIN") == "" {
		t.Skip("macOS only; set KOMANDO_TEST_KEYCHAIN=1")
	}
	freshHome(t)
	kc := filepath.Join(t.TempDir(), "komando-test.keychain-db")
	if out, err := exec.Command("security", "create-keychain", "-p", "test", kc).CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	defer exec.Command("security", "delete-keychain", kc).Run()
	exec.Command("security", "unlock-keychain", "-p", "test", kc).Run()
	roundTrip(t, kc)
	if strings.Contains(keychainService(), "/") {
		t.Error("service name carries the path")
	}
}

// keyFileVault is a vault with one secret and its key in vault.key, made
// with the keychain off; it returns that key.
func keyFileVault(t *testing.T) []byte {
	t.Helper()
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(store.Path("vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	return key
}

// stillKeyFile checks that a refused `komando secret keychain` left the
// vault as it was: its key in vault.key, and its secret readable.
func stillKeyFile(t *testing.T) {
	t.Helper()
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("mode %q, want keyfile", m)
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
}

// `komando secret keychain` never replaces another vault's key kept under
// this folder's name (Linux): it says so, and the vault keeps vault.key.
func TestKeyToKeychainItemExistsLinux(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	keyFileVault(t)
	other := strings.Repeat("ab", 32)
	kept := filepath.Join(toolDirs[0], "kept")
	if err := os.WriteFile(kept, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := KeyToKeychain()
	if !errors.Is(err, ErrKeychainTaken) || !strings.Contains(err.Error(), "moved aside") {
		t.Errorf("KeyToKeychain over another key: %v", err)
	}
	if strings.Contains(calls(), "store") {
		t.Errorf("the other key was replaced:\n%s", calls())
	}
	if b, _ := os.ReadFile(kept); string(b) != other {
		t.Errorf("the keychain item changed: %q", b)
	}
	stillKeyFile(t)
}

// A locked item (lookup finds nothing, gnome-keyring's search lists it)
// is not replaced either, and a search that fails stops the move.
func TestKeyToKeychainLockedOrUnsure(t *testing.T) {
	for name, search := range map[string]string{
		"locked":  `printf '[/org/freedesktop/secrets/collection/login/7]\nlabel = %s\n' "$4"`,
		"refused": `echo "secret-tool: The name org.freedesktop.secrets was not provided" >&2; exit 1`,
	} {
		t.Run(name, func(t *testing.T) {
			freshHome(t)
			keyFileVault(t)
			calls := scriptedSecretTool(t, `case "$1" in
  lookup) exit 1 ;;
  search) `+search+` ;;
  store) exit 0 ;;
esac
`)
			if _, err := KeyToKeychain(); err == nil || errors.Is(err, ErrKeychainTaken) {
				t.Errorf("KeyToKeychain: %v", err)
			}
			if strings.Contains(calls(), "store") {
				t.Errorf("a key was stored:\n%s", calls())
			}
			stillKeyFile(t)
		})
	}
}

// KeePassXC with its database locked: lookup and search show nothing, and
// `secret-tool store` would prompt to unlock, then replace the item. With
// the default collection locked, `komando secret keychain` stores nothing
// and asks for the keychain to be unlocked.
func TestKeyToKeychainCollectionLocked(t *testing.T) {
	freshHome(t)
	keyFileVault(t)
	calls := scriptedSecretTool(t, keePassXCLocked)
	lockTool(t, toolDirs[0], "gdbus", "echo '(<true>,)'")
	_, err := KeyToKeychain()
	if err == nil || errors.Is(err, ErrKeychainTaken) || !strings.Contains(err.Error(), "locked") || !strings.Contains(err.Error(), "unlock") {
		t.Errorf("KeyToKeychain with the collection locked: %v", err)
	}
	if strings.Contains(calls(), "search") || strings.Contains(calls(), "store") {
		t.Errorf("searched or stored with the collection locked:\n%s", calls())
	}
	stillKeyFile(t)
}

// The same key already in the keychain (a move that stopped before
// vault.json said so) finishes the move.
func TestKeyToKeychainSameKey(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	key := keyFileVault(t)
	if err := os.WriteFile(filepath.Join(toolDirs[0], "kept"), []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyToKeychain(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(calls(), "store") {
		t.Errorf("stored again:\n%s", calls())
	}
	if m := modeOnDisk(t); m != "keychain" {
		t.Errorf("mode %q, want keychain", m)
	}
}

// macOS: an item find-generic-password finds holds another key, so
// `komando secret keychain` refuses and runs no add.
func TestKeyToKeychainItemExistsMacOS(t *testing.T) {
	freshHome(t)
	keyFileVault(t)
	dir := t.TempDir()
	savedOS, savedSec := keychainOS, securityTool
	keychainOS, securityTool = "darwin", filepath.Join(dir, "security")
	t.Cleanup(func() { keychainOS, securityTool = savedOS, savedSec })
	script := `#!/bin/sh
echo "$1" >> "` + dir + `/calls"
case "$1" in
  find-generic-password) for a in "$@"; do [ "$a" = -w ] && { echo ` + strings.Repeat("cd", 32) + `; exit 0; }; done
    echo 'keychain: "login.keychain-db"' ;;
  -i) cat >> "` + dir + `/added" ;;
esac
`
	if err := os.WriteFile(securityTool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyToKeychain(); !errors.Is(err, ErrKeychainTaken) {
		t.Errorf("KeyToKeychain over another key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "added")); err == nil {
		t.Error("security -i ran an add")
	}
	stillKeyFile(t)
}
