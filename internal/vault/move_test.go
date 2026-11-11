package vault

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// writeOldVault writes vault.json as an earlier komando did: each value
// sealed with AES-GCM under scrypt(secret, salt), bound to its name.
func writeOldVault(t *testing.T, mode string, secret []byte, values map[string]string) {
	t.Helper()
	f := &file{Version: 1, Mode: mode, Salt: make([]byte, 16), Entries: map[string]*entry{}}
	rand.Read(f.Salt)
	if mode == "passphrase" {
		f.ScryptN = 1 << 10
	}
	a, err := f.aeadFor(secret)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range values {
		nonce := make([]byte, a.NonceSize())
		rand.Read(nonce)
		f.Entries[name] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, []byte(v), []byte(name)), UpdatedAt: time.Unix(1700000000, 0).UTC()}
	}
	b, _ := json.Marshal(f)
	if err := os.MkdirAll(store.Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path("vault.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// `komando seal` reads a vault of before in each of its key modes, and
// only reads: nothing is written, and no store is made.
func TestExportOldVault(t *testing.T) {
	values := map[string]string{"db-pass": "s3cret", "api": "tok-1"}
	check := func(t *testing.T) {
		t.Helper()
		names, err := OldNames()
		if err != nil || len(names) != 2 || names[0] != "api" {
			t.Fatalf("names %v %v", names, err)
		}
		got, err := ExportFiles()
		if err != nil {
			t.Fatal(err)
		}
		defer WipeSecrets(got)
		for k, v := range values {
			if string(got[k].Value) != v || got[k].UpdatedAt.Unix() != 1700000000 {
				t.Errorf("%s: %q %v", k, got[k].Value, got[k].UpdatedAt)
			}
		}
		if _, err := os.Stat(store.DBPath()); !os.IsNotExist(err) {
			t.Error("reading the old vault made a store")
		}
	}
	t.Run("key file", func(t *testing.T) {
		freshHome(t)
		key := make([]byte, keyLen)
		rand.Read(key)
		writeOldVault(t, "keyfile", key, values)
		if err := os.WriteFile(store.Path("vault.key"), key, 0o600); err != nil {
			t.Fatal(err)
		}
		check(t)
		if _, ok, _ := KeychainKeyOfOldVault(); ok {
			t.Error("a key-file vault has a keychain key")
		}
	})
	t.Run("passphrase", func(t *testing.T) {
		freshHome(t)
		writeOldVault(t, "passphrase", []byte("an old passphrase, long"), values)
		if _, err := ExportFiles(); err != ErrLocked {
			t.Fatalf("without the passphrase: %v", err)
		}
		usePass("an old passphrase, long")
		t.Cleanup(func() { usePass("") })
		check(t)
	})
	t.Run("keychain", func(t *testing.T) {
		freshHome(t)
		keychainStandIn(t, false)
		key := make([]byte, keyLen)
		rand.Read(key)
		if err := keychainPut(key); err != nil {
			t.Fatal(err)
		}
		writeOldVault(t, "keychain", key, values)
		check(t)
		if k, ok, err := KeychainKeyOfOldVault(); !ok || err != nil || len(k) == 0 {
			t.Errorf("keychain key: %v %v", ok, err)
		}
	})
	t.Run("missing key file", func(t *testing.T) {
		freshHome(t)
		writeOldVault(t, "keyfile", make([]byte, keyLen), values)
		if _, err := ExportFiles(); err == nil {
			t.Fatal("read without vault.key")
		}
	})
	t.Run("no vault", func(t *testing.T) {
		freshHome(t)
		if got, err := ExportFiles(); err != nil || len(got) != 0 {
			t.Fatalf("%v %v", got, err)
		}
	})
}
