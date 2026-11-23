package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/sgnd/komando/internal/sealkey"
)

// TestValueKeyScheme pins how the vault seals a value on a sealed home:
// the value key from the master key (32 bytes, AES-256), GCM, the name as
// additional data. The store's format-3 migration moves values to new
// names with the same scheme (store/migrate3_values.go), so a change here
// must change both.
func TestValueKeyScheme(t *testing.T) {
	master := bytes.Repeat([]byte{3}, 32)
	a, err := vaultAEADFrom(master)
	if err != nil {
		t.Fatal(err)
	}
	k, err := sealkey.Derive(master, sealkey.Values)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 32 {
		t.Fatalf("the value key is %d bytes", len(k))
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	same, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := a.Seal(nil, nonce, []byte("v"), []byte("db-pass"))
	if pt, err := same.Open(nil, nonce, sealed, []byte("db-pass")); err != nil || string(pt) != "v" {
		t.Fatalf("the scheme moved: %v", err)
	}
	if _, err := same.Open(nil, nonce, sealed, []byte("other")); err == nil {
		t.Error("a value opens under another name")
	}
}
