package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
case "$1" in store|search) s="$4" ;; *) s="$3" ;; esac
case "$s" in *generation) ;; *) echo "$1" >> "` + dir + `/calls" ;; esac
kept="` + dir + `/$(echo "$s" | tr ' /' '__')"
case "$1" in
  store) ` + fail + ` for a in "$@"; do [ ${#a} -ge 64 ] && { echo "a key in the arguments" >&2; exit 9; }; done; cat > "$kept" ;;
  lookup) [ -f "$kept" ] && cat "$kept" || exit 1 ;;
  search) if [ -f "$kept" ]; then printf '[/org/freedesktop/secrets/collection/login/1]\nlabel = %s\n' "$4"; fi ;;
  clear) rm -f "$kept" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	t.Setenv("KOMANDO_KEYCHAIN", "") // TestMain turned the keychain off
	return func() string {
		b, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return strings.TrimSpace(string(b))
	}
}

// keptItem is the file the stand-in keeps this folder's key item in.
func keptItem() string {
	return filepath.Join(toolDirs[0], strings.NewReplacer(" ", "_", "/", "_").Replace(keychainService()))
}

// modeOnDisk is the key mode the store names.
func modeOnDisk(t *testing.T) string {
	t.Helper()
	m, err := storeMeta()
	if err != nil {
		t.Fatal(err)
	}
	return m["key_mode"]
}

func noKeyFile(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
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
	// looked for a key and any item, stored a new one, read it back, and later reads use it
	if got := calls(); !strings.HasPrefix(got, "lookup\nsearch\nstore\nlookup") {
		t.Errorf("calls:\n%s", got)
	}
}

// Where the keychain cannot keep the key, the vault keeps it in vault.key
// and nothing is lost.
func TestNewVaultKeychainFails(t *testing.T) {
	freshHome(t)
	keychainStandIn(t, true)
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Fatalf("mode %q, want keyfile", m)
	}
	if _, err := os.Stat(storeKeyFile()); err != nil {
		t.Errorf("no vault.key: %v", err)
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
}

// A store moved aside leaves its change count in the keychain: komando
// stops instead of starting an empty store, never replaces the key, and
// the store put back opens.
func TestNewVaultKeepsKeychainKey(t *testing.T) {
	freshHome(t)
	calls := keychainStandIn(t, false)
	if err := Set("old", "kept value"); err != nil {
		t.Fatal(err)
	}
	aside := store.DBPath() + ".aside"
	if err := os.Rename(store.DBPath(), aside); err != nil {
		t.Fatal(err)
	}
	if err := Set("new", "v"); err == nil || !strings.Contains(err.Error(), "STATE_CORRUPT") && !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("a store moved aside: %v", err)
	}
	if n := strings.Count(calls(), "store"); n != 1 {
		t.Errorf("the key was stored %d times, want once:\n%s", n, calls())
	}
	if err := os.Rename(aside, store.DBPath()); err != nil {
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
	if _, err := KeyToKeychain(); err == nil || !strings.Contains(err.Error(), "KOMANDO_KEYCHAIN is off") {
		t.Errorf("secret keychain with the keychain off: %v", err)
	}
}

// A vault that exists keeps its mode: one made with vault.key (and empty,
// its key not made yet) gets vault.key, and a passphrase vault stays one.
// Only `komando secret keychain` moves a key.
func TestExistingVaultKeepsMode(t *testing.T) {
	freshHome(t)
	if err := Set("first", "v"); err != nil { // keychain off: a key file store
		t.Fatal(err)
	}
	calls := keychainStandIn(t, false)
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

// scriptedSecretTool plays the system's secret-tool with script (sh, after a
// line that logs the first word of every call); calls returns that log.
func scriptedSecretTool(t *testing.T, script string) (calls func() string) {
	t.Helper()
	dir := t.TempDir()
	savedOS, savedDirs := keychainOS, toolDirs
	keychainOS, toolDirs = "linux", []string{dir}
	t.Cleanup(func() { keychainOS, toolDirs = savedOS, savedDirs })
	body := "#!/bin/sh\necho \"$1\" >> \"" + dir + "/calls\"\n" + script
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	lockTool(t, dir, "gdbus", "echo '(<false>,)'") // the default collection is unlocked
	t.Setenv("KOMANDO_KEYCHAIN", "")
	return func() string {
		b, _ := os.ReadFile(filepath.Join(dir, "calls"))
		return strings.TrimSpace(string(b))
	}
}

// lockTool plays gdbus or busctl in dir (the system folder of the test),
// answering the question whether the default collection is locked with
// body (sh); an empty body removes the tool.
func lockTool(t *testing.T, dir, name, body string) {
	t.Helper()
	unixOnly(t, "sh scripts play the Linux Secret Service tools (secret-tool, gdbus)")
	p := filepath.Join(dir, name)
	if body == "" {
		_ = os.Remove(p)
		return
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A lookup that fails for another reason than "no such key" (a locked
// collection, a dismissed prompt) may hide the only key of a vault moved
// aside: `secret-tool store` would overwrite it, so nothing is stored and
// the new vault keeps its key in vault.key.
func TestNewVaultKeychainLocked(t *testing.T) {
	freshHome(t)
	calls := scriptedSecretTool(t, `case "$1" in
  lookup) echo "Cannot get secret of a locked object" >&2; exit 1 ;;
  store) exit 0 ;;
esac
`)
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("mode %q, want keyfile", m)
	}
	if strings.Contains(calls(), "store") {
		t.Errorf("a key was stored over one the keychain may hold:\n%s", calls())
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
}

// A keychain tool that never answers (an unlock prompt nobody sees, a slow
// D-Bus) does not hang the first secret: past newKeyTimeout the new vault
// keeps its key in vault.key.
func TestNewVaultKeychainHangs(t *testing.T) {
	freshHome(t)
	scriptedSecretTool(t, "exec sleep 30\n")
	saved := newKeyTimeout
	newKeyTimeout = 200 * time.Millisecond
	defer func() { newKeyTimeout = saved }()
	start := time.Now()
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the first secret took %v", d)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("mode %q, want keyfile", m)
	}
}

// newVaultNoStore makes the first secret against a scripted secret-tool and
// checks that nothing was stored in the keychain: the new vault keeps its
// key in vault.key, and the secret reads back.
func newVaultNoStore(t *testing.T, script string) {
	t.Helper()
	freshHome(t)
	calls := scriptedSecretTool(t, script)
	// a first run of a new script can be slow (macOS checks it); not the
	// keychain call newKeyTimeout should cut short
	_ = keychainCmd("warm-up").Run()
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if m := modeOnDisk(t); m != "keyfile" {
		t.Errorf("mode %q, want keyfile", m)
	}
	if !strings.Contains(calls(), "search") {
		t.Errorf("the keychain was not searched:\n%s", calls())
	}
	if strings.Contains(calls(), "store") {
		t.Errorf("a key was stored over one the keychain may hold:\n%s", calls())
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
}

// `secret-tool lookup` exits 1 with no output both when there is no item
// and when the item sits in a locked collection (a dismissed unlock
// prompt). gnome-keyring's `search --all` still lists the locked item, so
// nothing is stored over it.
func TestNewVaultKeychainItemLocked(t *testing.T) {
	newVaultNoStore(t, `case "$1" in
  lookup) exit 1 ;;
  search) [ "$2" = --all ] || exit 0
    printf '[/org/freedesktop/secrets/collection/login/7]\nlabel = %s\ncreated = 2026-01-01 00:00:00\nschema = org.freedesktop.Secret.Generic\nattribute.service = %s\nattribute.account = %s\n' "$4" "$4" "$6" ;;
  store) exit 0 ;;
esac
`)
}

// keePassXCLocked: KeePassXC with its database locked. lookup exits 1 with
// no output and search exits 0 with no output (it skips locked
// databases), though the database may hold the item; `store` would ask to
// unlock and then replace it.
const keePassXCLocked = `case "$1" in
  lookup) exit 1 ;;
  search) exit 0 ;;
  store) exit 0 ;;
esac
`

// newVaultLockAnswer makes the first secret against KeePassXC (locked or
// not, as the search shows nothing either way) with gdbus or busctl giving
// answer about the default collection, and says whether the key was stored.
func newVaultLockAnswer(t *testing.T, name, answer string) (stored bool) {
	t.Helper()
	freshHome(t)
	calls := scriptedSecretTool(t, keePassXCLocked)
	lockTool(t, toolDirs[0], "gdbus", "")
	lockTool(t, toolDirs[0], name, answer)
	if err := Set("db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("db-pass"); err != nil || v != "s3cret" {
		t.Errorf("Get: %q %v", v, err)
	}
	return strings.Contains(calls(), "store")
}

// A locked default collection (KeePassXC hides a locked database's items
// from a search), no tool to ask, or an answer komando does not know: no
// key is stored, and the new vault keeps its key in vault.key.
func TestNewVaultKeychainCollectionLocked(t *testing.T) {
	for name, c := range map[string]struct{ tool, answer string }{
		"gdbus locked":   {"gdbus", "echo '(<true>,)'"},
		"busctl locked":  {"busctl", "echo 'b true'"},
		"gdbus fails":    {"gdbus", "echo 'Error: GDBus.Error:org.freedesktop.DBus.Error.ServiceUnknown' >&2; exit 1"},
		"odd answer":     {"gdbus", "echo '(<\"no\">,)'"},
		"no tool to ask": {"gdbus", ""},
		"hangs":          {"busctl", "exec sleep 30"},
	} {
		t.Run(name, func(t *testing.T) {
			saved := newKeyTimeout
			newKeyTimeout = 500 * time.Millisecond
			defer func() { newKeyTimeout = saved }()
			if newVaultLockAnswer(t, c.tool, c.answer) {
				t.Error("a key was stored while the default collection may hide one")
			}
			if m := modeOnDisk(t); m != "keyfile" {
				t.Errorf("mode %q, want keyfile", m)
			}
		})
	}
}

// busctl, where there is no gdbus, says the collection is unlocked: the
// key goes into the keychain.
func TestNewVaultKeychainBusctl(t *testing.T) {
	if !newVaultLockAnswer(t, "busctl", "echo 'b false'") {
		t.Error("no key was stored with the default collection unlocked")
	}
}

// A search that fails (no D-Bus, a refused call) or answers only on
// stderr cannot tell whether an item is there: nothing is stored.
func TestNewVaultKeychainSearchFails(t *testing.T) {
	newVaultNoStore(t, `case "$1" in
  lookup) exit 1 ;;
  search) echo "secret-tool: Cannot autolaunch D-Bus without X11 \$DISPLAY" >&2; exit 1 ;;
  store) exit 0 ;;
esac
`)
	newVaultNoStore(t, `case "$1" in
  lookup) exit 1 ;;
  search) echo "secret-tool: some warning" >&2 ;;
  store) exit 0 ;;
esac
`)
}

// A search that never answers is "cannot tell" too, past newKeyTimeout.
func TestNewVaultKeychainSearchHangs(t *testing.T) {
	saved := newKeyTimeout
	newKeyTimeout = 500 * time.Millisecond
	defer func() { newKeyTimeout = saved }()
	newVaultNoStore(t, `case "$1" in
  lookup) exit 1 ;;
  search) exec sleep 30 ;;
  store) exit 0 ;;
esac
`)
}

// unixOnly skips a test on Windows, which cannot run the sh script that
// plays a keychain tool; why says which.
func unixOnly(t *testing.T, why string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix only: " + why)
	}
}
