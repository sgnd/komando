package sealdb

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A backup is flushed to disk before anyone relies on it: its file first,
// on every system (its folder as far as the system lets a folder be synced).
func TestBackupSyncsTheFile(t *testing.T) {
	_, d, _ := policyStore(t)
	var synced []string
	saved := syncOpened
	syncOpened = func(f *os.File) error { synced = append(synced, f.Name()); return saved(f) }
	t.Cleanup(func() { syncOpened = saved })
	dst := filepath.Join(t.TempDir(), "backup.db")
	if err := d.Backup(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if len(synced) == 0 || synced[0] != dst || !slices.Contains(synced, filepath.Dir(dst)) {
		t.Fatalf("synced %q, want the file %s first, then its folder", synced, dst)
	}
}
