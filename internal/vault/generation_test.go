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

// macKeychains plays macOS's security tool with a default keychain and
// any keychain file named on the command line, each item kept in a file
// of dir named after its keychain and service. items lists the items a
// keychain ("default", or a file's path) holds, by service.
func macKeychains(t *testing.T) (items func(kc string) map[string]string) {
	t.Helper()
	unixOnly(t, "an sh script plays macOS's security tool")
	dir := t.TempDir()
	savedOS, savedSec := keychainOS, securityTool
	keychainOS, securityTool = "darwin", filepath.Join(t.TempDir(), "security")
	t.Cleanup(func() { keychainOS, securityTool = savedOS, savedSec })
	script := `#!/bin/sh
d="` + dir + `"
[ "$1" = default-keychain ] && { echo '    "/Users/x/Library/Keychains/login.keychain-db"'; exit 0; }
if [ "$1" = -i ]; then read -r line; eval "set -- $line"; fi
op="$1"; shift
svc=""; val=""; kc="default"; w=""; u=""
while [ $# -gt 0 ]; do
  case "$1" in
    -a|-l) shift 2 ;;
    -s) svc="$2"; shift 2 ;;
    -w) if [ "$op" = add-generic-password ]; then val="$2"; shift 2; else w=1; shift; fi ;;
    -U) u=1; shift ;;
    *) kc="$1"; shift ;;
  esac
done
f="$d/$(printf '%s' "$kc" | tr '/' '_')=$(printf '%s' "$svc" | tr ' ' '_')"
case "$op" in
  find-generic-password) [ -f "$f" ] || exit 44; [ -n "$w" ] && cat "$f"; exit 0 ;;
  add-generic-password) if [ -f "$f" ] && [ -z "$u" ]; then echo "security: The specified item already exists in the keychain."; exit 0; fi
    printf '%s\n' "$val" > "$f" ;;
  delete-generic-password) rm -f "$f" ;;
esac
`
	if err := os.WriteFile(securityTool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	return func(kc string) map[string]string {
		prefix := strings.ReplaceAll(kc, "/", "_") + "="
		got := map[string]string{}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if svc, ok := strings.CutPrefix(e.Name(), prefix); ok {
				b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				got[strings.ReplaceAll(svc, "_", " ")] = strings.TrimSpace(string(b))
			}
		}
		return got
	}
}

// A person's separate keychain (KOMANDO_KEYCHAIN set to a keychain file
// on a Mac) keeps the store's key and its change count together. An AI
// agent's path is used for neither: its calls use the default keychain
// for both, so a store never has its key in one keychain and its count in
// another. An agent cannot open a store whose key is in the person's
// file, and nothing it does leaves the person's store split.
func TestAgentKeychainPathNotUsed(t *testing.T) {
	agent := false
	savedAgent := AgentCall
	t.Cleanup(func() { AgentCall = savedAgent })
	AgentCall = func() bool { return agent }
	t.Run("a person's store in a keychain file", func(t *testing.T) {
		freshHome(t)
		items := macKeychains(t)
		file := filepath.Join(t.TempDir(), "separate.keychain-db")
		t.Setenv("KOMANDO_KEYCHAIN", file)
		agent = false
		if err := Set(store.Save(), "db-pass", "s3cret"); err != nil {
			t.Fatal(err)
		}
		if m := modeOnDisk(t); m != "keychain" {
			t.Fatalf("mode %q, want keychain", m)
		}
		inFile := items(file)
		if len(inFile) != 2 || inFile[keychainService()] == "" || inFile[genService()] == "" {
			t.Fatalf("the key and the count are not both in the person's file: %v", inFile)
		}
		if d := items("default"); len(d) != 0 {
			t.Fatalf("the default keychain got %v", d)
		}
		// the agent, with the same KOMANDO_KEYCHAIN: refused, and nothing written
		store.Close()
		agent = true
		_, err := Get("db-pass")
		if err == nil || !strings.Contains(err.Error(), "KOMANDO_KEYCHAIN path is not used") {
			t.Fatalf("an agent opened a store whose key is in the person's file: %v", err)
		}
		if err := Set(store.Save(), "other", "v"); err == nil {
			t.Fatal("an agent changed a store whose key is in the person's file")
		}
		if d := items("default"); len(d) != 0 {
			t.Fatalf("the agent's call wrote to the default keychain: %v", d)
		}
		// the person's setup still works, the count still beside the key
		store.Close()
		agent = false
		if v, err := Get("db-pass"); err != nil || v != "s3cret" {
			t.Fatalf("the person after the agent: %q %v", v, err)
		}
		before := items(file)[genService()]
		if err := Set(store.Save(), "other", "v"); err != nil {
			t.Fatal(err)
		}
		if after := items(file)[genService()]; after == before {
			t.Errorf("the count in the person's file stayed %s", after)
		}
	})
	t.Run("an agent's store with a keychain file set", func(t *testing.T) {
		freshHome(t)
		items := macKeychains(t)
		file := filepath.Join(t.TempDir(), "agent.keychain-db")
		t.Setenv("KOMANDO_KEYCHAIN", file)
		agent = true
		if err := Set(store.Save(), "db-pass", "s3cret"); err != nil {
			t.Fatal(err)
		}
		if m := modeOnDisk(t); m != "keychain" {
			t.Fatalf("mode %q, want keychain", m)
		}
		if f := items(file); len(f) != 0 {
			t.Fatalf("the agent's file got %v", f)
		}
		d := items("default")
		if len(d) != 2 || d[keychainService()] == "" || d[genService()] == "" {
			t.Fatalf("the key and the count are not both in the default keychain: %v", d)
		}
		store.Close()
		before := d[genService()]
		if err := Set(store.Save(), "other", "v"); err != nil {
			t.Fatalf("the agent's next run: %v", err)
		}
		if after := items("default")[genService()]; after == before {
			t.Errorf("the count in the default keychain stayed %s", after)
		}
		if f := items(file); len(f) != 0 {
			t.Fatalf("the agent's file got %v", f)
		}
	})
}
