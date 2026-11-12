package netx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSameProgram(t *testing.T) {
	for _, c := range []struct {
		name, exe  string
		fold, want bool
	}{
		{"komando", "komando", false, true},
		{"komando-tunnel-x", "komando-tunnel-xyz-long-name", false, true}, // Linux keeps 15 characters
		{"sleep", "komando", false, false},
		{"", "komando", false, false},
		{"Komando.EXE", "komando.exe", true, true}, // Windows does not care about case
		{"Komando.EXE", "komando.exe", false, false},
		{"notepad.exe", "komando.exe", true, false},
	} {
		if got := sameProgram(c.name, c.exe, c.fold); got != c.want {
			t.Errorf("sameProgram(%q, %q, %v) = %v", c.name, c.exe, c.fold, got)
		}
	}
}

// isProgram reads the name of a running program from the system: this test
// runs on every system, Windows included, where ps does not exist.
func TestIsProgramSelf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !isProgram(os.Getpid(), filepath.Base(self)) {
		name, err := programName(os.Getpid())
		t.Fatalf("isProgram(self, %q) = false; the system says %q (%v)", filepath.Base(self), name, err)
	}
	if isProgram(os.Getpid(), "surely-not-this-program") {
		t.Fatal("isProgram matched another program's name")
	}
}
