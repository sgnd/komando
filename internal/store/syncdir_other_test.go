//go:build !windows

package store

import (
	"path/filepath"
	"testing"
)

// Off Windows the folder of a renamed backup is opened and synced: a
// folder that is not there is an error.
func TestSyncDirSyncsTheFolder(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("a folder that is not there synced")
	}
}
