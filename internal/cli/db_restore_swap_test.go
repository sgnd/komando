package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// The file a person said yes to is the file that is restored: one that is
// rewritten while the approval window is open stops with FILE_CHANGED
// before the database is opened. (Before, the restore opened the path
// again and ran whatever was there.)
func TestRestoreStopsWhenTheFileChangesAfterTheCheck(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://app@127.0.0.1:1/app?sslmode=disable")
	file := filepath.Join(t.TempDir(), "f.sql")
	if err := os.WriteFile(file, []byte("INSERT INTO t VALUES (1);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	windows := 0
	saved := askOnScreen
	askOnScreen = func(_ *call, text string) (bool, bool) {
		windows++
		// the agent swaps the file while the person reads the window
		os.WriteFile(file, []byte("COPY t TO PROGRAM 'id';\n"), 0o600)
		return true, true
	}
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	resetApproval()
	_, e := invRun(t, "db", "restore", "pg", "--from", file, "--allow-dangerous")
	if windows == 0 {
		t.Fatal("no approval window was opened")
	}
	if e == nil || e.Code != "FILE_CHANGED" {
		t.Fatalf("want FILE_CHANGED, got %+v", e)
	}
}
