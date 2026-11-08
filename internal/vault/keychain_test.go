package vault

import (
	"crypto/cipher"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func freshHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "")
	os.Unsetenv("KOMANDO_VAULT_PASS")
	aeadMu.Lock()
	aeadCache = map[string]cipher.AEAD{}
	aeadMu.Unlock()
}

func roundTrip(t *testing.T) {
	t.Helper()
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
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
store="` + dir + `/kept"
case "$1" in
  store) for a in "$@"; do [ ${#a} -ge 64 ] && { echo "a key in the arguments" >&2; exit 9; }; done; cat > "$store" ;;
  lookup) [ -f "$store" ] && cat "$store" || exit 1 ;;
  clear) rm -f "$store" ;;
esac
`
	os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755)
	savedDirs := toolDirs
	toolDirs = []string{dir} // the stand-in plays the system's secret-tool
	defer func() { toolDirs = savedDirs }()
	roundTrip(t)
}

// A secret-tool or security found through PATH is never run: it would be
// handed the vault key, or could hand komando a key of its choosing.
func TestKeychainToolsNotFromPath(t *testing.T) {
	freshHome(t)
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
	t.Setenv("KOMANDO_KEYCHAIN", kc)
	roundTrip(t)
	if strings.Contains(keychainService(), "/") {
		t.Error("service name carries the path")
	}
}
