package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadOwnKeyFromHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, "id"), []byte("X"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadPrivateKey(&Key{Path: "~/id"}); err != nil || string(b) != "X" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestSealedManagedKey(t *testing.T) {
	sealedStore(t)
	p, err := WriteManagedKey("k", []byte("PRIVATE-KEY-BYTES"), []byte("PUB\n"))
	if err != nil {
		t.Fatal(err)
	}
	k := &Key{Name: "k", Path: p, Managed: true}
	if !SealedKey(k) {
		t.Fatalf("path %q", p)
	}
	if b, err := ReadPrivateKey(k); err != nil || string(b) != "PRIVATE-KEY-BYTES" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := os.Stat(Path("keys")); !os.IsNotExist(err) {
		t.Fatal("keys/ made in a sealed home")
	}
	raw, _ := os.ReadFile(Path(StoreFile))
	if strings.Contains(string(raw), "PRIVATE-KEY") {
		t.Fatal("private key readable in store.db")
	}
	if err := RemoveManagedKey(k); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(k); err == nil {
		t.Fatal("removed key still read")
	}
}
