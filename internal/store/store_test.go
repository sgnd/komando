package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func tmpFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			left = append(left, e.Name())
		}
	}
	return left
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(p, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte(`{"a":2}`), 0o640); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != `{"a":2}` || fi.Mode().Perm() != 0o640 {
		t.Fatalf("got %q mode %o", b, fi.Mode().Perm())
	}
	if left := tmpFiles(t, dir); left != nil {
		t.Fatalf("temporary files left: %v", left)
	}
}

// A failed write reports the error and leaves no temporary file behind.
func TestWriteFileAtomicCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir()
	// the rename cannot replace a folder that has something in it
	p := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(filepath.Join(p, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("{}"), 0o600); err == nil {
		t.Fatal("writing over a folder succeeded")
	}
	if left := tmpFiles(t, dir); left != nil {
		t.Fatalf("temporary files left: %v", left)
	}
}

// An empty state.json is what a crash can leave behind; reading it as a
// fresh install would silently drop protected flags and the host key policy.
func TestLoadRefusesEmptyStateFile(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	if _, err := Load(); err != nil {
		t.Fatalf("no state file yet: %v", err)
	}
	if err := os.WriteFile(Path("state.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STATE_CORRUPT" || !strings.Contains(oe.Hint, "restore it from a backup") || !strings.Contains(err.Error(), "corrupt state file") {
		t.Fatalf("empty state file: %v", err)
	}
	if err := Update(func(s *State) error { return nil }); err == nil {
		t.Fatal("Update saved over an empty state file")
	}
}

func TestLockSerializes(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	var mu sync.Mutex
	inside, most := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := Lock(".test.lock")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			most = max(most, inside)
			mu.Unlock()
			// a little work while holding the lock
			_ = WriteFileAtomic(Path("x"), []byte("x"), 0o600)
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Fatalf("%d holders at once", most)
	}
}
