package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fileState is what a dry run must leave as it was: content, mode and
// modification time.
type fileState struct {
	sum   [32]byte
	mode  fs.FileMode
	mtime time.Time
}

// treeOf is every file and folder under root.
func treeOf(t *testing.T, root string) map[string]fileState {
	t.Helper()
	m := map[string]fileState{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
	return m
}

// The dry run of the migration reads a format-2 store and says what the
// move would do: counts only, never a name or a value, and it writes
// nothing (every file byte-equal, the same mode and time, no new file).
func TestMigrationPreviewWritesNothing(t *testing.T) {
	home := format2Store(t)
	Close()
	time.Sleep(10 * time.Millisecond) // a write now would show in the times
	before := treeOf(t, home)
	p, err := PreviewMigration(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if after := treeOf(t, home); !maps.Equal(before, after) {
		t.Fatalf("the dry run changed the home:\nbefore %v\nafter  %v", before, after)
	}
	if p.Format != "2" || !p.WouldMove || p.Counts["host"][0] != 12 || p.Counts["credential"][1] == 0 || len(p.WouldRefuse) != 0 {
		t.Fatalf("preview %+v", p)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	t.Logf("the dry run of the fixture:\n%s", b) // the example output in the report
	for _, n := range []string{"web1", "db1", "win1", "10.0.0", "pg-pass", "deploy", "ovpn", sentinel} {
		if strings.Contains(string(b), n) {
			t.Errorf("the dry run names %q: %s", n, b)
		}
	}
}

// What the migration would refuse is named by kind and field only.
func TestMigrationPreviewRefusals(t *testing.T) {
	format2Store(t)
	format2Edit(t, func(s *State) { s.Hosts["web2"].PasswordRef = "secret:missing-pw" })
	Close()
	p, err := PreviewMigration(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.WouldMove || len(p.WouldRefuse) != 1 || p.WouldRefuse[0] != "host: field password_ref names a secret that does not exist" {
		t.Fatalf("preview %+v", p)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "web2") || strings.Contains(string(b), "missing-pw") {
		t.Errorf("the dry run names a record or a secret: %s", b)
	}
}

// A store of format 3 has nothing to move; a home without a store neither.
func TestMigrationPreviewNothingToDo(t *testing.T) {
	migrated(t)
	Close()
	if p, err := PreviewMigration(context.Background(), nil); err != nil || p.Format != "3" || p.WouldMove {
		t.Fatalf("format 3: %+v %v", p, err)
	}
	sealedHome(t)
	if p, err := PreviewMigration(context.Background(), nil); err != nil || p.Format != "none" || p.WouldMove {
		t.Fatalf("no store: %+v %v", p, err)
	}
}
