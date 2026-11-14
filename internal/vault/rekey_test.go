package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

const (
	oldPass = "correct horse battery staple"
	newPass = "a much longer and newer passphrase"
)

// usePass is what KOMANDO_VAULT_PASS gave this process.
func usePass(p string) {
	passMu.Lock()
	pass = p
	passMu.Unlock()
}

// passHome is a fresh state directory whose new vault takes passphrase p,
// with a cheap scrypt cost so the tests stay fast.
func passHome(t *testing.T, p string) {
	t.Helper()
	freshHome(t)
	usePass(p)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n; usePass("") })
}

// vaultView is the vault in the store, with the store's key settings.
type vaultView struct {
	file
	Mode    string
	Salt    []byte
	ScryptN int
}

// vaultFile is the vault in the store, with the store's key settings.
func vaultFile(t *testing.T) vaultView {
	t.Helper()
	f, err := loadSealed()
	if err != nil {
		t.Fatal(err)
	}
	m, err := storeMeta()
	if err != nil {
		t.Fatal(err)
	}
	v := vaultView{file: *f, Mode: m["key_mode"], Salt: []byte(m["salt"])}
	v.ScryptN, _ = strconv.Atoi(m["scrypt_n"])
	return v
}

// vaultBytes is the store file as it is on disk.
func vaultBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSet(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if err := Set(store.Save(), k, v); err != nil {
			t.Fatal(err)
		}
	}
}

func wantValues(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, want := range kv {
		if v, err := Get(k); err != nil || v != want {
			t.Errorf("%s = %q, %v; want %q", k, v, err, want)
		}
	}
}

var someSecrets = map[string]string{"db-pass": "s3cret value", "api-token": "tok-123", "empty-ish": " "}

// A new passphrase opens every secret, the old one none, and the dates stay.
func TestChangePassphrase(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	before := vaultFile(t)
	time.Sleep(10 * time.Millisecond)

	res, err := ChangeKey(store.Save(), "", newPass)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "passphrase" || res.To != "passphrase" || res.Secrets != len(someSecrets) || res.Removed != "" || res.Left != "" {
		t.Errorf("result %+v", res)
	}
	after := vaultFile(t)
	if after.Mode != "passphrase" || after.ScryptN != PassphraseN || bytes.Equal(after.Salt, before.Salt) {
		t.Errorf("mode %s, scrypt %d, salt changed %v", after.Mode, after.ScryptN, !bytes.Equal(after.Salt, before.Salt))
	}
	for name, e := range before.Entries {
		a := after.Entries[name]
		if a == nil || !a.UpdatedAt.Equal(e.UpdatedAt) || bytes.Equal(a.Nonce, e.Nonce) {
			t.Errorf("%s: before %+v after %+v", name, e, a)
		}
	}
	wantValues(t, someSecrets) // this process now holds the new passphrase
	usePass(newPass)
	wantValues(t, someSecrets)
	usePass(oldPass)
	if err := Opens(""); !errors.Is(err, ErrWrongKey) {
		t.Errorf("Opens with the old passphrase: %v", err)
	}
	if err := Opens(newPass); err != nil {
		t.Errorf("Opens with the new passphrase: %v", err)
	}
}

// A wrong current passphrase changes nothing, and the right one given
// directly (KOMANDO_VAULT_PASS already holds the new one) works.
func TestChangeKeyWrongOldPassphrase(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	raw := vaultBytes(t)

	usePass("correct horse battery stapel")
	if _, err := ChangeKey(store.Save(), "", newPass); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong KOMANDO_VAULT_PASS: %v", err)
	}
	if _, err := ChangeKey(store.Save(), "not the passphrase at all", newPass); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong old passphrase: %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("the store changed")
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Errorf("a store.key appeared: %v", err)
	}

	usePass(newPass) // the person changed KOMANDO_VAULT_PASS first
	if _, err := ChangeKey(store.Save(), oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	wantValues(t, someSecrets)
}

// One secret that does not decrypt stops the change before anything is
// written: the vault stays byte for byte as it was.
func TestChangeKeyPartialFailure(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	if err := changeSealed(func(f *file) error {
		e := f.Entries["empty-ish"]
		e.Data = bytes.Clone(e.Data)
		e.Data[0] ^= 0xff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := vaultBytes(t)

	_, err := ChangeKey(store.Save(), "", newPass)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte(`"empty-ish"`)) {
		t.Fatalf("want the broken secret named: %v", err)
	}
	if !bytes.Equal(b, vaultBytes(t)) {
		t.Fatal("the store changed")
	}
	wantValues(t, map[string]string{"db-pass": "s3cret value", "api-token": "tok-123"})
}

func TestChangeKeyRefusesShortPassphrase(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	raw := vaultBytes(t)
	if _, err := ChangeKey(store.Save(), "", "fourteen chars"); !errors.Is(err, ErrShortPassphrase) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("the store changed")
	}
}

// The key in the keychain is removed once the vault has its passphrase.
func TestKeychainToPassphrase(t *testing.T) {
	passHome(t, "")
	fakeSecretTool(t)
	t.Setenv("KOMANDO_KEYCHAIN", "off") // the vault starts with vault.key
	mustSet(t, someSecrets)
	t.Setenv("KOMANDO_KEYCHAIN", "")
	if _, err := KeyToKeychain(); err != nil {
		t.Fatal(err)
	}
	res, err := ChangeKey(store.Save(), "", newPass)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "keychain" || res.To != "passphrase" || res.Removed != "keychain" {
		t.Errorf("result %+v", res)
	}
	if _, err := keychainGet(); err == nil {
		t.Error("the old key is still in the keychain")
	}
	wantValues(t, someSecrets)
}

// With no vault yet, the first one is made with the passphrase.
func TestChangeKeyWithoutVault(t *testing.T) {
	passHome(t, "")
	res, err := ChangeKey(store.Save(), "", newPass)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "" || res.To != "passphrase" || res.Secrets != 0 {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Errorf("a store.key was made: %v", err)
	}
	mustSet(t, map[string]string{"first": "value-1"})
	wantValues(t, map[string]string{"first": "value-1"})
	if f := vaultFile(t); f.Mode != "passphrase" {
		t.Errorf("mode %s", f.Mode)
	}
}

func TestChangeKeyDryRun(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	raw := vaultBytes(t)
	if _, err := ChangeKey(store.Preview(), "", newPass); !errors.Is(err, store.ErrDryRun) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("the store changed")
	}
}

// fakeSecretTool puts a stand-in secret-tool in the only folder komando
// looks in, keeps one secret in a file, and uses the Linux keychain code
// with it.
func fakeSecretTool(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	savedOS, savedDirs := keychainOS, toolDirs
	keychainOS = "linux"
	toolDirs = []string{dir} // the stand-in plays the system's secret-tool
	t.Cleanup(func() { keychainOS, toolDirs = savedOS, savedDirs })
	script := `#!/bin/sh
case "$1" in store|search) s="$4" ;; *) s="$3" ;; esac
store="` + dir + `/$(echo "$s" | tr ' /' '__')"
case "$1" in
  store) cat > "$store" ;;
  lookup) [ -f "$store" ] && cat "$store" || exit 1 ;;
  clear) rm -f "$store" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	lockTool(t, dir, "gdbus", "echo '(<false>,)'") // the default collection is unlocked
	t.Setenv("KOMANDO_KEYCHAIN", "")               // TestMain turned the keychain off
	if _, err := KeychainTool(); err != nil {
		t.Fatalf("the stand-in secret-tool is not used: %v", err)
	}
}
