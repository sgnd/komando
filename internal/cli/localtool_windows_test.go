package cli

import (
	"os"
	"path/filepath"
	"strings"
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
	if dirs := windowsToolDirs(); len(dirs) == 0 || !toolSafe(tcl, filepath.Join(windowsDir(), "System32", "cmd.exe")) {
		t.Errorf("cmd.exe in the Windows folder counts as changeable (%q)", dirs)
	}
}

// Inside the Windows folder only System32 and SysWOW64 count: folders such
// as Temp and Tasks can be written by every user of the computer.
func TestToolSafeLeavesWritableWindowsFoldersOut(t *testing.T) {
	win := windowsDir()
	if win == "" {
		t.Fatal("Windows names no Windows folder")
	}
	for _, p := range []string{`Temp\pg_dump.exe`, `Tasks\pg_dump.exe`, `Tracing\pg_dump.exe`, `pg_dump.exe`} {
		if toolSafe(tcl, filepath.Join(win, p)) {
			t.Errorf("%s counts as safe", p)
		}
	}
	if !toolSafe(tcl, filepath.Join(win, "System32", "cmd.exe")) {
		t.Error("System32 counts as changeable")
	}
	t.Setenv("SystemRoot", t.TempDir())
	if !strings.HasPrefix(strings.ToLower(systemPathFor()), strings.ToLower(win)) {
		t.Errorf("a login program's PATH follows SystemRoot from the environment: %s", systemPathFor())
	}
}

// A program under Program Files counts only when it and its folders belong
// to the administrators and no one else may write them: an installer may
// give every user write access to its folder. A file this user made fails
// the same check komando makes there (no test can write under Program
// Files without an administrator).
func TestToolSafeChecksOwnerAndAccessList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pg_dump.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if adminsAlone(p) {
		t.Error("a file this user owns and may write counts as the administrators' alone")
	}
	sys := filepath.Join(windowsDir(), "System32")
	if !pathAdminsAlone(filepath.Join(sys, "cmd.exe"), sys) {
		t.Error("cmd.exe in System32 does not count as the administrators' alone")
	}
	if pathAdminsAlone(p, sys) {
		t.Error("a file outside the folder passed the walk up to it")
	}
}
