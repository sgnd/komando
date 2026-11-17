//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// A komando folder that was already there with others' access (a copy, an
// unzip, a chmod) stayed so: ensureHome only set 0700 on a folder it made.
// It now makes komando's own folder private again, and leaves any other
// folder KOMANDO_HOME names as it is.
func TestEnsureHomeTightensKomandoFolder(t *testing.T) {
	h := filepath.Join(t.TempDir(), "k")
	if err := os.Mkdir(h, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(h, 0o755)
	t.Setenv("KOMANDO_HOME", h)
	if err := ensureHome(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(h); fi.Mode().Perm() != 0o755 {
		t.Fatalf("a folder that is not komando's changed: %v", fi.Mode())
	}
	if err := os.WriteFile(filepath.Join(h, StoreFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureHome(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(h); fi.Mode().Perm() != 0o700 {
		t.Errorf("komando's folder stayed %v", fi.Mode())
	}
}
