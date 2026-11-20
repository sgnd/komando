package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// C214: a --from-file file is read once per command. The window and the
// secret or config map that is sent use the same bytes, even when the file
// changes in between.
func TestKubectlFromFileIsReadOnce(t *testing.T) {
	setHome(t, t.TempDir())
	t.Cleanup(func() { tcl.manifests = nil })
	p := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(p, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := readFromFile(tcl, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := readFromFile(tcl, p)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != "first\n" || string(b) != "first\n" {
		t.Errorf("reads %q then %q, want the first bytes both times", a, b)
	}
}
