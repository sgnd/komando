package cli

import (
	"crypto/sha256"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

type fileState struct {
	sum   [32]byte
	mode  fs.FileMode
	mtime time.Time
}

// treeOf is every file and folder under each root that exists: content,
// mode and modification time.
func treeOf(t *testing.T, roots ...string) map[string]fileState {
	t.Helper()
	m := map[string]fileState{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) && p == root {
				return filepath.SkipDir
			}
			if err != nil {
				return err
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			st := fileState{mode: fi.Mode(), mtime: fi.ModTime()}
			if !d.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				st.sum = sha256.Sum256(b)
			}
			m[p] = st
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// The person's dry run before the move to format 3 (owner, 2026-11-27):
// `komando doctor --dry-run` on a store of format 2 says what the move
// would do, in counts, and writes nothing: every file of the home is
// byte-equal with the same mode and time, and no file is new.
func TestDoctorDryRunPreviewsTheMove(t *testing.T) {
	invHome(t)
	sealdb.CreateFormat = 2
	t.Cleanup(func() { sealdb.CreateFormat = sealdb.Format })
	if _, err := store.DB(true); err != nil {
		t.Fatal(err)
	}
	store.Close()
	sealdb.CreateFormat = sealdb.Format
	roots := []string{store.Home()}
	for _, dir := range []func() (string, error){os.UserCacheDir, os.UserConfigDir} {
		if d, err := dir(); err == nil {
			roots = append(roots, filepath.Join(d, "komando"))
		}
	}
	time.Sleep(10 * time.Millisecond) // a write now would show in the times
	before := treeOf(t, roots...)
	d := mustRun(t, "doctor", "--dry-run")
	if after := treeOf(t, roots...); !maps.Equal(before, after) {
		t.Fatalf("the dry run changed the home:\nbefore %v\nafter  %v", before, after)
	}
	if d["format"] != "2" || d["would_move"] != true {
		t.Fatalf("dry run: %s", asJSON(d))
	}
	if f, err := sealdb.Peek(t.Context(), store.DBPath()); err != nil || f["format"] != "2" {
		t.Fatalf("the store moved: %v %v", f, err)
	}
	s, err := runCache(t, "-o", "text", "doctor", "--dry-run")
	if err != nil || !strings.Contains(s, "format 2") || !strings.Contains(s, "nothing was written") {
		t.Fatalf("text: %v\n%s", err, s)
	}
}

// A dry run never moves the store, whoever runs it.
func TestMigrateCallForDryRun(t *testing.T) {
	cl := testCall()
	setGate(cl, true, gateDryRun)
	if c := migrateCallFor(cl, "doctor"); c.Way != store.MigrateRefuse || !strings.Contains(c.Why, "dry run") {
		t.Fatalf("a dry run: way %d, why %q", c.Way, c.Why)
	}
}
