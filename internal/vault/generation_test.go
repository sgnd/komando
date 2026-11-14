package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The generation item: written, read back, replaced and removed, beside
// (not in place of) the store's key, through a stand-in secret-tool.
func TestGenerationItem(t *testing.T) {
	freshHome(t)
	t.Setenv("KOMANDO_KEYCHAIN", "")
	dir := t.TempDir()
	saved := keychainOS
	keychainOS = "linux"
	t.Cleanup(func() { keychainOS = saved })
	// one file per service name
	script := `#!/bin/sh
d="` + dir + `"
case "$1" in
  store) cat > "$d/$(echo "$4" | tr ' /' '__')" ;;
  lookup) f="$d/$(echo "$3" | tr ' /' '__')"; [ -f "$f" ] && cat "$f" || exit 1 ;;
  clear) rm -f "$d/$(echo "$3" | tr ' /' '__')" ;;
esac
`
	os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755)
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	savedDirs := toolDirs
	toolDirs = []string{dir}
	t.Cleanup(func() { toolDirs = savedDirs })

	if _, ok, err := genGet(); err != nil || ok {
		t.Fatalf("before: %v %v", ok, err)
	}
	if err := keychainPut(make([]byte, 32)); err != nil { // the store's key
		t.Fatal(err)
	}
	for _, n := range []uint64{3, 9, 4} {
		if err := genSet(n); err != nil {
			t.Fatal(err)
		}
		if got, ok, err := genGet(); err != nil || !ok || got != n {
			t.Fatalf("set %d, got %d %v %v", n, got, ok, err)
		}
	}
	if k, err := keychainGet(); err != nil || len(k) != 32 {
		t.Fatalf("the key was touched: %v", err)
	}
	genDel()
	if _, ok, _ := genGet(); ok {
		t.Fatal("the generation stayed")
	}
}

// An agent's KOMANDO_KEYCHAIN=off does not hide the store's change count:
// with it, an agent could move store.db and store.key aside (or put an old
// copy back) and komando would use that store with no old-copy check. A
// person's or a script's off still means no keychain at all.
func TestAgentKeychainOffKeepsCount(t *testing.T) {
	freshHome(t)
	t.Setenv("KOMANDO_KEYCHAIN", "")
	dir := t.TempDir()
	saved := keychainOS
	keychainOS = "linux"
	t.Cleanup(func() { keychainOS = saved })
	script := `#!/bin/sh
d="` + dir + `"
case "$1" in
  store) cat > "$d/$(echo "$4" | tr ' /' '__')" ;;
  lookup) f="$d/$(echo "$3" | tr ' /' '__')"; [ -f "$f" ] && cat "$f" || exit 1 ;;
esac
`
	os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755)
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	savedDirs := toolDirs
	toolDirs = []string{dir}
	t.Cleanup(func() { toolDirs = savedDirs })
	agent := false
	AgentCall = func() bool { return agent }
	t.Cleanup(func() { AgentCall = nil })

	if err := genSet(7); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	if _, ok, err := genGet(); ok || err == nil {
		t.Fatalf("a person's off still read the keychain: %v %v", ok, err)
	}
	agent = true
	if n, ok, err := genGet(); err != nil || !ok || n != 7 {
		t.Fatalf("an agent's off hid the count: %d %v %v", n, ok, err)
	}
	if err := genSet(9); err != nil {
		t.Fatalf("an agent's off stopped the count rising: %v", err)
	}
	// and the store sees it: no store.db while the keychain remembers one
	var oe *out.Error
	if _, err := store.DB(true); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
		t.Fatalf("an agent's off let komando start an empty store: %v", err)
	}
}

// An agent's KOMANDO_KEYCHAIN path counts no more than its "off": pointed
// at a new, empty keychain file it would find no change count, and komando
// would start an empty store over one the agent moved aside. An agent's
// count is read and kept in the default keychain; a person's path is
// still used.
func TestAgentKeychainPathKeepsCount(t *testing.T) {
	unixOnly(t, "an sh script plays macOS's security tool")
	freshHome(t)
	dir := t.TempDir()
	other := filepath.Join(dir, "new.keychain-db")
	t.Setenv("KOMANDO_KEYCHAIN", other)
	savedOS, savedSec := keychainOS, securityTool
	keychainOS, securityTool = "darwin", filepath.Join(dir, "security")
	t.Cleanup(func() { keychainOS, securityTool = savedOS, savedSec })
	// the default keychain remembers change 7; the new file holds nothing
	script := `#!/bin/sh
last=""; for a in "$@"; do last="$a"; done
case "$1" in
  default-keychain) echo '    "/Users/x/Library/Keychains/login.keychain-db"' ;;
  find-generic-password) [ "$last" = "` + other + `" ] && exit 44; echo 7 ;;
  -i) cat >> "` + dir + `/added" ;;
esac
`
	if err := os.WriteFile(securityTool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	agent := false
	AgentCall = func() bool { return agent }
	t.Cleanup(func() { AgentCall = nil })
	if _, ok, err := genGet(); err != nil || ok {
		t.Fatalf("a person's keychain file: %v %v", ok, err)
	}
	agent = true
	if n, ok, err := genGet(); err != nil || !ok || n != 7 {
		t.Fatalf("an agent's keychain file hid the count: %d %v %v", n, ok, err)
	}
	if err := genSet(9); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "added")); strings.Contains(string(b), other) {
		t.Errorf("an agent's count went into its own keychain file: %s", b)
	}
	var oe *out.Error
	if _, err := store.DB(true); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
		t.Fatalf("an agent's keychain file let komando start an empty store: %v", err)
	}
	if _, err := os.Stat(store.DBPath()); !os.IsNotExist(err) {
		t.Fatalf("a store was made: %v", err)
	}
}
