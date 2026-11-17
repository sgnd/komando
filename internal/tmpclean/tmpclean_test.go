package tmpclean

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoveAllAndForget(t *testing.T) {
	dir := t.TempDir()
	kept := filepath.Join(dir, "kept")
	gone := filepath.Join(dir, "gone")
	for _, p := range []string{kept, gone} {
		if err := os.MkdirAll(filepath.Join(p, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	forget := Add(kept)
	Add(gone)
	forget() // its own code is done with it
	RemoveAll()
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Errorf("a kept path was not removed: %v", err)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("a forgotten path was removed: %v", err)
	}
	if Kept() != 0 {
		t.Errorf("%d paths still kept", Kept())
	}
}

func TestSweepOnlyOldOwnLeftovers(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * Stale)
	mk := func(name string, when time.Time) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(".komando-123.tmp", old)
	fresh := mk(".komando-456.tmp", time.Now()) // a run still going
	other := mk("credentials.tmp", old)
	bare := mk(".komando-.tmp", old) // the pattern alone is not a name komando makes
	Sweep(dir, ".komando-", ".tmp")
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("an old leftover stayed")
	}
	for _, p := range []string{fresh, other, bare} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed", filepath.Base(p))
		}
	}
}
