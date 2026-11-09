package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

func vaultFile(t *testing.T) file {
	t.Helper()
	var f file
	b, err := os.ReadFile(store.Path("vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func vaultBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(store.Path("vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSet(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		if err := Set(k, v); err != nil {
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

	res, err := ChangeKey("", newPass)
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
	if _, err := Get("db-pass"); err == nil {
		t.Error("the old passphrase still opens the vault")
	}
	if err := Set("x", "y"); err == nil {
		t.Error("Set with the old passphrase worked")
	}
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
	if _, err := ChangeKey("", newPass); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong KOMANDO_VAULT_PASS: %v", err)
	}
	if _, err := ChangeKey("not the passphrase at all", newPass); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong old passphrase: %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("vault.json changed")
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Errorf("a vault.key appeared: %v", err)
	}

	usePass(newPass) // the person changed KOMANDO_VAULT_PASS first
	if _, err := ChangeKey(oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	wantValues(t, someSecrets)
}

// One secret that does not decrypt stops the change before anything is
// written: the vault stays byte for byte as it was.
func TestChangeKeyPartialFailure(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	f := vaultFile(t)
	f.Entries["empty-ish"].Data[0] ^= 0xff
	b, _ := json.MarshalIndent(f, "", "  ")
	if err := os.WriteFile(store.Path("vault.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ChangeKey("", newPass)
	if !errors.Is(err, ErrWrongKey) || !bytes.Contains([]byte(err.Error()), []byte(`"empty-ish"`)) {
		t.Fatalf("want the broken secret named: %v", err)
	}
	if !bytes.Equal(b, vaultBytes(t)) {
		t.Fatal("vault.json changed")
	}
	wantValues(t, map[string]string{"db-pass": "s3cret value", "api-token": "tok-123"})
}

func TestChangeKeyRefusesShortPassphrase(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	raw := vaultBytes(t)
	if _, err := ChangeKey("", "fourteen chars"); !errors.Is(err, ErrShortPassphrase) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("vault.json changed")
	}
}

// A key-file vault gets a passphrase and loses vault.key; --off goes back
// to a new random key in vault.key.
func TestKeyFileToPassphraseAndBack(t *testing.T) {
	passHome(t, "")
	mustSet(t, someSecrets)
	kp := store.Path("vault.key")
	oldKey, err := os.ReadFile(kp)
	if err != nil {
		t.Fatal(err)
	}
	before := vaultFile(t)
	if _, err := ChangeKey("", ""); !errors.Is(err, ErrNoPassphrase) {
		t.Errorf("--off on a key-file vault: %v", err)
	}

	res, err := ChangeKey("", newPass)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "keyfile" || res.To != "passphrase" || res.Removed != "vault.key" || res.Left != "" {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(kp); !os.IsNotExist(err) {
		t.Errorf("vault.key is still there: %v", err)
	}
	if f := vaultFile(t); f.Mode != "passphrase" || f.ScryptN != PassphraseN {
		t.Errorf("mode %s, scrypt %d", f.Mode, f.ScryptN)
	}
	wantValues(t, someSecrets)
	if LeftoverKeyFile() != "" {
		t.Error("a leftover vault.key is reported")
	}

	res, err = ChangeKey("", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "passphrase" || res.To != "keyfile" || res.Removed != "" {
		t.Errorf("result %+v", res)
	}
	newKey, err := os.ReadFile(kp)
	if err != nil || len(newKey) != keyLen || bytes.Equal(newKey, oldKey) {
		t.Fatalf("vault.key: %d bytes, the old key again %v, %v", len(newKey), bytes.Equal(newKey, oldKey), err)
	}
	f := vaultFile(t)
	if f.Mode != "keyfile" || bytes.Equal(f.Salt, before.Salt) {
		t.Errorf("mode %s, the first salt again %v", f.Mode, bytes.Equal(f.Salt, before.Salt))
	}
	usePass("") // KOMANDO_VAULT_PASS is not needed any more
	wantValues(t, someSecrets)
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
	res, err := ChangeKey("", newPass)
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
	res, err := ChangeKey("", newPass)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "" || res.To != "passphrase" || res.Secrets != 0 {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Errorf("a vault.key was made: %v", err)
	}
	mustSet(t, map[string]string{"first": "value-1"})
	wantValues(t, map[string]string{"first": "value-1"})
	if f := vaultFile(t); f.Mode != "passphrase" {
		t.Errorf("mode %s", f.Mode)
	}
}

// A vault.key the vault does not use (it opens old copies of the vault) is
// reported, so doctor can say so.
func TestLeftoverKeyFile(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	if LeftoverKeyFile() != "" {
		t.Fatal("reported without a vault.key")
	}
	kp := store.Path("vault.key")
	if err := os.WriteFile(kp, make([]byte, keyLen), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LeftoverKeyFile(); got != kp {
		t.Errorf("got %q", got)
	}
}

func TestChangeKeyDryRun(t *testing.T) {
	passHome(t, oldPass)
	mustSet(t, someSecrets)
	raw := vaultBytes(t)
	store.DryRun = true
	defer func() { store.DryRun = false }()
	if _, err := ChangeKey("", newPass); !errors.Is(err, store.ErrDryRun) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(raw, vaultBytes(t)) {
		t.Fatal("vault.json changed")
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
store="` + dir + `/kept"
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
