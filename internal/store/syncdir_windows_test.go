package store

import (
	"path/filepath"
	"testing"
)

// On Windows a folder cannot be opened to be synced (Access is denied), so
// the folder sync is skipped: not even a missing folder is opened. The
// backup file itself is synced (sealdb's TestBackupSyncsTheFile).
func TestSyncDirSkippedOnWindows(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "gone")); err != nil {
		t.Fatalf("the folder sync ran on Windows: %v", err)
	}
}
