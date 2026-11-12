package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestStoreMasterKeyFile(t *testing.T) {
	freshHome(t) // keychain off: a key file
	k, meta, err := storeMaster(nil, true)
	if err != nil || len(k) != keyLen || meta["key_mode"] != "keyfile" {
		t.Fatalf("%d %v %v", len(k), meta, err)
	}
	if fi, err := os.Stat(storeKeyFile()); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("store.key: %v", err)
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Fatal("the store made vault.key")
	}
	again, _, err := storeMaster(meta, false)
	if err != nil || !bytes.Equal(again, k) {
		t.Fatalf("reopen: %v", err)
	}
	if err := os.WriteFile(storeKeyFile(), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := storeMaster(meta, false); !errors.Is(err, ErrKey) {
		t.Fatalf("short key: %v", err)
	}
	os.Remove(storeKeyFile())
	if _, _, err := storeMaster(meta, false); !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("missing key: %v", err)
	}
}

func TestStoreMasterPassphrase(t *testing.T) {
	freshHome(t)
	n := PassphraseN
	PassphraseN = 1 << 10
	t.Cleanup(func() { PassphraseN = n })
	t.Setenv("KOMANDO_VAULT_PASS", "correct horse")
	k, meta, err := storeMaster(nil, true)
	if err != nil || meta["key_mode"] != "passphrase" || meta["salt"] == "" {
		t.Fatalf("%v %v", meta, err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("a passphrase store wrote a key file")
	}
	again, _, _ := storeMaster(meta, false)
	if !bytes.Equal(again, k) {
		t.Fatal("same passphrase, other key")
	}
	t.Setenv("KOMANDO_VAULT_PASS", "wrong")
	if other, _, _ := storeMaster(meta, false); bytes.Equal(other, k) {
		t.Fatal("wrong passphrase, same key")
	}
	t.Setenv("KOMANDO_VAULT_PASS", "")
	if _, _, err := storeMaster(meta, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("no passphrase: %v", err)
	}
	bad := map[string]string{"key_mode": "passphrase", "salt": "zz", "scrypt_n": "1024"}
	t.Setenv("KOMANDO_VAULT_PASS", "x")
	if _, _, err := storeMaster(bad, false); !errors.Is(err, ErrKey) {
		t.Fatalf("damaged settings: %v", err)
	}
	if _, _, err := storeMaster(map[string]string{"key_mode": "tpm"}, false); !errors.Is(err, ErrKey) {
		t.Fatalf("unknown mode: %v", err)
	}
}

// The keychain item a macOS stand-in returns opens a keychain-mode store.
func TestStoreMasterKeychain(t *testing.T) {
	freshHome(t)
	t.Setenv("KOMANDO_KEYCHAIN", "")
	dir := t.TempDir()
	savedOS, savedSec := keychainOS, securityTool
	keychainOS, securityTool = "darwin", filepath.Join(dir, "security")
	t.Cleanup(func() { keychainOS, securityTool = savedOS, savedSec })
	script := "#!/bin/sh\ncase \"$1\" in default-keychain) echo login.keychain-db ;; find-generic-password) for a in \"$@\"; do [ \"$a\" = -w ] && { echo " + strings.Repeat("cd", 32) + "; exit 0; }; done ;; esac\n"
	if err := os.WriteFile(securityTool, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	k, meta, err := storeMaster(nil, true)
	if err != nil || meta["key_mode"] != "keychain" {
		t.Fatalf("%v %v", meta, err)
	}
	again, _, err := storeMaster(meta, false)
	if err != nil || !bytes.Equal(again, k) {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := os.Stat(storeKeyFile()); !os.IsNotExist(err) {
		t.Fatal("a keychain store wrote a key file")
	}
}

// The vault package sets the store's key source, and a sealed store made
// with it opens again in a new process (a fresh DB cache).
func TestStoreKeySourceWired(t *testing.T) {
	freshHome(t)
	if store.KeySource == nil {
		t.Fatal("vault did not set store.KeySource")
	}
	if _, err := store.DB(true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path(store.StoreFile)); err != nil {
		t.Fatal(err)
	}
}
