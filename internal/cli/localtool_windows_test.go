package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// The folders a program counts as safe in come from Windows: an AI agent
// that sets ProgramFiles or SystemRoot to a folder of its own does not
// make its program there count as safe.
func TestToolSafeIgnoresTheEnvironment(t *testing.T) {
	own := t.TempDir()
	p := filepath.Join(own, "pg_dump.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)"} {
		t.Setenv(v, own)
	}
	if toolSafe(tcl, p) {
		t.Error("a program in a folder the environment names counts as safe")
	}
	win, err := os.UserHomeDir() // any folder that is not Windows' own
	if err == nil && toolSafe(tcl, filepath.Join(win, "x.exe")) {
		t.Error("a program in the home folder counts as safe")
	}
	if !toolSafe(tcl, filepath.Join(windowsToolDirs()[0], "System32", "cmd.exe")) {
		t.Error("cmd.exe in the Windows folder counts as changeable")
	}
}
