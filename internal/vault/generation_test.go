package vault

import (
	"errors"
	"os"
	"path/filepath"
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
