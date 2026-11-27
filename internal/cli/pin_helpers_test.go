package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// pinCount is the check that a table-driven pin ran every case: ran is the
// cases the loop reached, want the cases counted before the loop started.
// A table with no case fails too: it pins nothing.
func pinCount(what string, ran, want int) error {
	switch {
	case want == 0:
		return fmt.Errorf("no %s to run: the table is empty", what)
	case ran != want:
		return fmt.Errorf("ran %d %ss, want %d: a case was skipped (or added without its count)", ran, what, want)
	}
	return nil
}

func TestPinCount(t *testing.T) {
	tests := []struct {
		name      string
		ran, want int
		fails     bool
	}{
		{"all ran", 5, 5, false},
		{"one skipped", 4, 5, true},
		{"none ran", 0, 5, true},
		{"more than counted", 6, 5, true},
		{"empty table", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := pinCount("case", tt.ran, tt.want); (err != nil) != tt.fails {
				t.Errorf("pinCount(%d, %d) = %v, want an error: %v", tt.ran, tt.want, err, tt.fails)
			}
		})
	}
}

// snapshotDirs copies what lies in dirs now and gives the function that
// puts exactly that back: files written since are removed, files changed
// are written again, with their modes. A pin that seeds a home once and
// runs many cases uses it so each case starts from the seed, as a home of
// its own would. The folders themselves stay (the program may stand in one).
func snapshotDirs(t *testing.T, dirs ...string) (restore func(t *testing.T)) {
	t.Helper()
	copies := t.TempDir()
	for i, d := range dirs {
		if err := copyDirInto(d, filepath.Join(copies, fmt.Sprint(i))); err != nil {
			t.Fatalf("snapshot of %s: %v", d, err)
		}
	}
	return func(t *testing.T) {
		t.Helper()
		for i, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if err := os.RemoveAll(filepath.Join(d, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
			if err := copyDirInto(filepath.Join(copies, fmt.Sprint(i)), d); err != nil {
				t.Fatalf("restore of %s: %v", d, err)
			}
		}
	}
}

// copyDirInto copies the files and folders under src into dst, which it
// makes if needed. Anything else (a link, a socket) is an error: a seed
// holds none, and a copy would not be the seed.
func copyDirInto(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		info, err := e.Info()
		if err != nil {
			return err
		}
		switch {
		case e.IsDir():
			return os.MkdirAll(to, 0o700)
		case info.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(to, b, info.Mode().Perm())
		}
		return fmt.Errorf("%s: not a file or folder (%v)", p, info.Mode())
	})
}

func TestSnapshotDirsRestores(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b"), []byte("seed b"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := snapshotDirs(t, dir)
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("changed"), 0o600)
	_ = os.Remove(filepath.Join(dir, "sub", "b"))
	_ = os.WriteFile(filepath.Join(dir, "new"), []byte("new"), 0o600)
	restore(t)
	for name, want := range map[string]string{"a": "seed", "sub/b": "seed b"} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); err == nil {
		t.Error("a file written after the snapshot is still there")
	}
}
