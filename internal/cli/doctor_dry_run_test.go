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

// filesOf is tree without its folders.
func filesOf(tree map[string]fileState) map[string]fileState {
	m := map[string]fileState{}
	for p, st := range tree {
		if !st.mode.IsDir() {
			m[p] = st
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
	// a real komando home is 0700; komando tightens a wider one at start
	if err := os.Chmod(store.Home(), 0o700); err != nil {
		t.Fatal(err)
	}
	// komando's other folders: the files in them (the test binary shares
	// these folders, so their own times are not compared)
	var shared []string
	for _, dir := range []func() (string, error){os.UserCacheDir, os.UserConfigDir} {
		if d, err := dir(); err == nil {
			shared = append(shared, filepath.Join(d, "komando"))
		}
	}
	time.Sleep(10 * time.Millisecond) // a write now would show in the times
	before, beforeShared := treeOf(t, store.Home()), filesOf(treeOf(t, shared...))
	d := mustRun(t, "doctor", "--dry-run")
	if after := treeOf(t, store.Home()); !maps.Equal(before, after) {
		t.Fatalf("the dry run changed the home:\nbefore %v\nafter  %v", before, after)
	}
	if after := filesOf(treeOf(t, shared...)); !maps.Equal(beforeShared, after) {
		t.Fatalf("the dry run changed komando's other folders:\nbefore %v\nafter  %v", beforeShared, after)
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

// C558: the dry run's text gives the steps of the fix word for word, as
// the move does when it stops (the store builds both from one list).
func TestDoctorDryRunTextGivesTheFix(t *testing.T) {
	pv := store.MigrationPreview{Format: "2", WouldRefuse: []string{"host: field password_ref names an outside store (vault), which a login no longer reads"},
		Fix: []string{"install komando " + store.LastFormat2Release + ", the last release", "there, do it", "then run `komando update` again"}}
	s := migrationPreview{pv}.Text()
	want := "the move to format 3 would stop:\n  ✗ " + pv.WouldRefuse[0] + "\nto fix it:\n  1. " + pv.Fix[0] + "\n  2. " + pv.Fix[1] + "\n  3. " + pv.Fix[2] + "\n"
	if !strings.Contains(s, want) {
		t.Fatalf("text\n%s\nlacks\n%s", s, want)
	}
}
