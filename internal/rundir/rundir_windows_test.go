package rundir

import (
	"os"
	"path/filepath"
	"testing"
)

// While komando holds the copy, no other handle may write it, truncate it,
// rename it or delete it: Go's own os.OpenFile shares a file for writing,
// so a writer through the path would land in the very bytes komando reads.
func TestCreateRefusesOtherWriters(t *testing.T) {
	dir := t.TempDir()
	f, err := Create(dir, "restore")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer f.Close()
	name := f.Name()
	if _, err := f.WriteString("checked"); err != nil {
		t.Fatalf("write through the handle: %v", err)
	}
	if w, err := os.OpenFile(name, os.O_WRONLY, 0); err == nil {
		w.Close()
		t.Error("another handle opened the copy for writing")
	}
	if err := os.WriteFile(name, []byte("other"), 0o600); err == nil {
		t.Error("os.WriteFile wrote over the copy")
	}
	if err := os.Rename(name, filepath.Join(dir, "moved.tmp")); err == nil {
		t.Error("the copy was renamed")
	}
	if err := os.Remove(name); err == nil {
		t.Error("the copy was removed")
	}
	got := make([]byte, 7)
	if _, err := f.ReadAt(got, 0); err != nil || string(got) != "checked" {
		t.Errorf("the handle reads %q (%v), want %q", got, err, "checked")
	}
}

// Closing the handle removes the copy, so a run that ends without its own
// clean-up (a second Ctrl-C, a kill) leaves nothing.
func TestCreateCopyGoesWithTheHandle(t *testing.T) {
	f, err := Create(t.TempDir(), "restore")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.Close()
	if _, err := os.Lstat(f.Name()); !os.IsNotExist(err) {
		t.Errorf("the copy is still there after close: %v", err)
	}
}
