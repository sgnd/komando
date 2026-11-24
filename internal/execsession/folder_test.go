//go:build !windows

package execsession

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const testID = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"

// runPrelude runs the folder prelude under sh with HOME set to home, then
// prints "made $d". It gives the output and the exit code.
func runPrelude(t *testing.T, home string) (string, int) {
	t.Helper()
	text, err := FolderScript(testID)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", text+`; echo "made $d"`)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	b, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(b), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), 0
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// U5: the folder and its parents are 0700, made new by the login user.
func TestFolderScriptMakesPrivateFolders(t *testing.T) {
	home := t.TempDir()
	got, code := runPrelude(t, home)
	want := filepath.Join(home, ".komando", "sessions", testID)
	if code != 0 || strings.TrimSpace(got) != "made "+want {
		t.Fatalf("exit %d, %q; want made %s", code, got, want)
	}
	for _, p := range []string{filepath.Join(home, ".komando"), filepath.Join(home, ".komando", "sessions"), want} {
		if m := mode(t, p); !m.IsDir() || m.Perm() != 0o700 {
			t.Errorf("%s: mode %v, want a 0700 folder", p, m)
		}
	}
}

// An existing root keeps its contents and is made private.
func TestFolderScriptTightensAWideRoot(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".komando")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, code := runPrelude(t, home); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if m := mode(t, root).Perm(); m != 0o700 {
		t.Errorf("root mode %o, want 700", m)
	}
}

// U7: a link, a file or an existing session folder is refused as unsafe:
// nothing is made through it.
func TestFolderScriptRefusesUnsafe(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, home string) string // returns a path that must stay untouched
	}{
		{"root is a link", func(t *testing.T, home string) string {
			elsewhere := t.TempDir()
			if err := os.Symlink(elsewhere, filepath.Join(home, ".komando")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(elsewhere, "sessions")
		}},
		{"sessions is a link", func(t *testing.T, home string) string {
			elsewhere := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, ".komando"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(home, ".komando", "sessions")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(elsewhere, testID)
		}},
		{"sessions is a file", func(t *testing.T, home string) string {
			if err := os.Mkdir(filepath.Join(home, ".komando"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".komando", "sessions"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, ".komando", "sessions", testID)
		}},
		{"the session folder exists", func(t *testing.T, home string) string {
			if err := os.MkdirAll(filepath.Join(home, ".komando", "sessions", testID), 0o700); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, ".komando", "sessions", testID, "planted")
		}},
		{"the session folder is a link", func(t *testing.T, home string) string {
			elsewhere := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".komando", "sessions"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(home, ".komando", "sessions", testID)); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(elsewhere, "planted")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			untouched := tt.plant(t, home)
			got, code := runPrelude(t, home)
			if code != ExitUnsafe || strings.Contains(got, "made") {
				t.Fatalf("exit %d, %q; want exit %d and nothing made", code, got, ExitUnsafe)
			}
			// not there, or its parent is a file: either way nothing was made
			if _, err := os.Lstat(untouched); !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				t.Errorf("%s exists: %v", untouched, err)
			}
		})
	}
}

// U17 (the unit part): a home where nothing can be made is "no folder",
// which runs the command without a session, not a refusal.
func TestFolderScriptNoFolder(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	if got, code := runPrelude(t, home); code != ExitNoFolder {
		t.Fatalf("exit %d, %q; want %d", code, got, ExitNoFolder)
	}
	if got, code := runPrelude(t, ""); code != ExitNoFolder {
		t.Fatalf("no HOME: exit %d, %q; want %d", code, got, ExitNoFolder)
	}
}

func TestFolderScriptChecksTheID(t *testing.T) {
	if _, err := FolderScript("../x"); err == nil {
		t.Fatal("a bad ID made shell text")
	}
}
