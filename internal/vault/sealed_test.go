package vault

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func sealedVault(t *testing.T) {
	t.Helper()
	freshHome(t)
	store.UseSealedForNewHomes(true)
	t.Cleanup(func() { store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1") })
}

func TestSealedVault(t *testing.T) {
	sealedVault(t)
	if l, err := List(); err != nil || len(l) != 0 {
		t.Fatalf("empty: %v %v", l, err)
	}
	if s, err := Check(); err != nil || !s.NoVaultYet {
		t.Fatalf("check before: %+v %v", s, err)
	}
	for k, v := range map[string]string{"db": "s3cret-value", "api": "tok-123", "old": "x"} {
		if err := Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := Get("db"); err != nil || v != "s3cret-value" {
		t.Fatalf("get %q %v", v, err)
	}
	if err := Set("db", "changed"); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get("db"); v != "changed" {
		t.Fatalf("after change %q", v)
	}
	if err := Delete("old"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if err := Copy("api", "api2", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename("api2", "api3", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename("api", "db", false); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto a name: %v", err)
	}
	if err := RenameMany(map[string]string{"api3": "api4"}); err != nil {
		t.Fatal(err)
	}
	l, _ := List()
	var names []string
	for _, i := range l {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "api,api4,db" {
		t.Fatalf("names %v", names)
	}
	if v, _ := Get("api4"); v != "tok-123" {
		t.Fatalf("renamed value %q", v)
	}
	// no vault.json, nothing readable in the store, and the mode is the
	// store's own
	for _, f := range []string{"vault.json", "vault.key"} {
		if _, err := os.Stat(store.Path(f)); !os.IsNotExist(err) {
			t.Fatalf("%s written in a sealed home", f)
		}
	}
	b, _ := os.ReadFile(store.Path(store.StoreFile))
	for _, w := range []string{"changed", "tok-123", "api4"} {
		if strings.Contains(string(b), w) {
			t.Fatalf("%q readable in store.db", w)
		}
	}
	if s, err := Check(); err != nil || s.Mode != "keyfile" {
		t.Fatalf("check %+v %v", s, err)
	}
	if err := KeyToFile(); err != nil { // a key file already: nothing to do
		t.Fatalf("key move: %v", err)
	}
}

func TestSealedVaultParallel(t *testing.T) {
	sealedVault(t)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Set(fmt.Sprintf("s%d", i), "v"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if l, _ := List(); len(l) != 12 {
		t.Fatalf("%d secrets, want 12", len(l))
	}
}

// The inventory and the vault share the store; a secret set beside a
// server change keeps both.
func TestSealedVaultBesideInventory(t *testing.T) {
	sealedVault(t)
	if err := store.Update(func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web", PasswordRef: "secret:db"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Set("db", "pw"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil || st.Hosts["web"] == nil {
		t.Fatalf("inventory lost: %v", err)
	}
	if v, err := Resolve("secret:db"); err != nil || v != "pw" {
		t.Fatalf("resolve %q %v", v, err)
	}
}

// A sealed store's key: from store.key to a passphrase, to another
// passphrase, back to a key file, and into the keychain and out; every
// secret and server survives, and the old key no longer opens the store.
func TestSealedKeyChanges(t *testing.T) {
	sealedVault(t)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n })
	if err := store.Update(func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Set("db", "pw-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateRuntime(func(s *store.State) error {
		s.Jobs["j1"] = &store.Job{ID: "j1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey("", "short"); !errors.Is(err, ErrShortPassphrase) {
		t.Fatalf("short: %v", err)
	}
	if _, err := ChangeKey("", ""); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	both := func(step string) {
		t.Helper()
		if v, err := Get("db"); err != nil || v != "pw-1" {
			t.Fatalf("%s: secret %q %v", step, v, err)
		}
		if st, err := store.Load(); err != nil || st.Hosts["web"] == nil || st.Jobs["j1"] == nil {
			t.Fatalf("%s: inventory or runtime %v", step, err)
		}
	}
	r, err := ChangeKey("", "first passphrase, long")
	if err != nil || r.From != "keyfile" || r.To != "passphrase" || r.Secrets != 1 || r.Removed != "store.key" {
		t.Fatalf("to passphrase: %+v %v", r, err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("store.key left")
	}
	both("passphrase")
	if err := Opens("wrong passphrase entirely"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong passphrase opens: %v", err)
	}
	r, err = ChangeKey("first passphrase, long", "second passphrase, long")
	if err != nil || r.To != "passphrase" {
		t.Fatalf("new passphrase: %+v %v", r, err)
	}
	both("second passphrase")
	if err := Opens("first passphrase, long"); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the old passphrase still opens: %v", err)
	}
	r, err = ChangeKey("", "")
	if err != nil || r.To != "keyfile" {
		t.Fatalf("to key file: %+v %v", r, err)
	}
	both("key file")
	if s, _ := Check(); s.Mode != "keyfile" {
		t.Fatalf("mode %q", s.Mode)
	}
}

// fakeKeychainFiles puts a secret-tool that keeps items in files on PATH,
// so the keychain moves run without a real keychain.
func fakeKeychainFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	saved := keychainOS
	keychainOS = "linux"
	t.Cleanup(func() { keychainOS = saved })
	script := `#!/bin/sh
d="` + dir + `"
f() { echo "$d/$(echo "$1" | tr ' /' '__')"; }
case "$1" in
  store) cat > "$(f "$4")" ;;
  lookup) [ -f "$(f "$3")" ] && cat "$(f "$3")" || exit 1 ;;
  search) if [ -f "$(f "$4")" ]; then printf '[/org/freedesktop/secrets/collection/login/1]\nlabel = %s\n' "$4"; fi ;;
  clear) rm -f "$(f "$3")" ;;
esac
`
	os.WriteFile(dir+"/secret-tool", []byte(script), 0o755)
	lockTool(t, dir, "gdbus", "echo '(<false>,)'")
	savedDirs := toolDirs
	toolDirs = []string{dir}
	t.Cleanup(func() { toolDirs = savedDirs })
}

func TestSealedKeyToKeychainAndBack(t *testing.T) {
	sealedVault(t)
	fakeKeychainFiles(t)
	if err := Set("db", "pw"); err != nil { // a key file store
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	if _, err := KeyToKeychain(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("store.key left after the move")
	}
	if s, _ := Check(); s.Mode != "keychain" {
		t.Fatalf("mode %q", s.Mode)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("with the keychain: %q %v", v, err)
	}
	if err := KeyToFile(); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("back in a key file: %q %v", v, err)
	}
	if _, err := keychainGet(); err == nil {
		t.Fatal("the key stayed in the keychain")
	}
}

// A move to the keychain whose change count cannot be saved leaves the
// store on its key file: it must not end up a keychain store with no
// count, which would never open again.
func TestSealedKeyToKeychainCountFails(t *testing.T) {
	sealedVault(t)
	fakeKeychainFiles(t)
	if err := Set("db", "pw"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMANDO_KEYCHAIN", "")
	saved := store.GenerationKeeper
	store.GenerationKeeper.Set = func(uint64) error { return errors.New("keychain locked") }
	_, err := KeyToKeychain()
	store.GenerationKeeper = saved
	if err == nil {
		t.Fatal("the move worked without a change count")
	}
	if s, _ := Check(); s.Mode != "keyfile" {
		t.Fatalf("mode %q after a failed move", s.Mode)
	}
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("after a failed move: %q %v", v, err)
	}
}

// A change to a key file that stopped halfway is finished or undone by
// the next command, never left stuck.
func TestSealedKeyFileChangeStoppedHalfway(t *testing.T) {
	sealedVault(t)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n })
	if err := Set("db", "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey("", "a passphrase, long enough"); err != nil {
		t.Fatal(err)
	}
	// stopped before the commit: a store.key.new nobody uses
	if err := os.WriteFile(newKeyFilePath(), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChangeKey("a passphrase, long enough", ""); err != nil {
		t.Fatalf("a leftover store.key.new blocks the change: %v", err)
	}
	if _, err := os.Stat(newKeyFilePath()); !os.IsNotExist(err) {
		t.Fatal("store.key.new left after the change")
	}
	// stopped after the commit, before the rename
	if err := os.Rename(storeKeyFile(), newKeyFilePath()); err != nil {
		t.Fatal(err)
	}
	// a new process: the store file is new to this one, the key not known
	b, err := os.ReadFile(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(store.DBPath()+".tmp", b, 0o600)
	if err := os.Rename(store.DBPath()+".tmp", store.DBPath()); err != nil {
		t.Fatal(err)
	}
	aeadMu.Lock()
	aeadCache = map[string]cipher.AEAD{}
	aeadMu.Unlock()
	if v, err := Get("db"); err != nil || v != "pw" {
		t.Fatalf("store.key.new not taken as the key: %q %v", v, err)
	}
	if _, err := os.Stat(storeKeyFile()); err != nil {
		t.Fatalf("store.key not in place: %v", err)
	}
}
