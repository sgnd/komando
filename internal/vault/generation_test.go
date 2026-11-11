package vault

import (
	"os"
	"path/filepath"
	"testing"
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
