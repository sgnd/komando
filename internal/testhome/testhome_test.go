package testhome

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("CLAUDECODE", "1") // as when an AI agent starts the tests
	os.Setenv("KOMANDO_AGENT", "1")
	done := Use()
	code := m.Run()
	done()
	os.Exit(code)
}

// After Use the home folder of the test binary is a new, empty folder,
// not the one the tests were started with.
func TestUseGivesAThrowawayHome(t *testing.T) {
	h, err := os.UserHomeDir()
	if err != nil || h != Dir() || Dir() == "" {
		t.Fatalf("os.UserHomeDir() = %q, %v; Dir() = %q", h, err, Dir())
	}
	if Real() == "" || sameFolder(Real(), h) {
		t.Fatalf("the home is still the real one: %q", h)
	}
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"} {
		if v := os.Getenv(k); !strings.HasPrefix(v, Dir()) {
			t.Errorf("%s = %q is outside %s", k, v, Dir())
		}
	}
	if d, err := os.UserConfigDir(); err != nil || !strings.HasPrefix(d, Dir()) {
		t.Errorf("os.UserConfigDir() = %q, %v", d, err)
	}
	// the tests run as a script: for an agent komando reads the home from
	// the user database, which HOME does not move
	for _, v := range []string{"CLAUDECODE", "KOMANDO_AGENT"} {
		if _, set := os.LookupEnv(v); set {
			t.Errorf("%s is still set: komando would take the home folder from the user database", v)
		}
	}
	if !ours(Dir()) || ours(Real()) || ours(filepath.Join(os.TempDir(), "elsewhere")) || ours("") {
		t.Error("only a komando-test-home folder in the temp folder counts as a parent's home")
	}
	if os.Getenv(childEnv) != Dir() {
		t.Error("a test binary started by a test would make a home of its own")
	}
}

func sameFolder(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

type fakeTB struct{ failed string }

func (f *fakeTB) Helper()                           {}
func (f *fakeTB) Fatalf(format string, args ...any) { f.failed = fmt.Sprintf(format, args...) }

// Path lets through the throwaway home and t.TempDir, and fails a test
// for anything else, the real home first of all.
func TestPath(t *testing.T) {
	for _, ok := range []string{filepath.Join(Dir(), ".ssh", "id_ed25519"), filepath.Join(t.TempDir(), "x"), Dir()} {
		f := &fakeTB{}
		if Path(f, ok); f.failed != "" {
			t.Errorf("%s: %s", ok, f.failed)
		}
	}
	// a link in the temp folder that leads out of it is where it leads
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "key")
		if err := os.Symlink(filepath.Join(Real(), "komando-testhome-no-such-file"), link); err != nil {
			t.Fatal(err)
		}
		f := &fakeTB{}
		if Path(f, link); f.failed == "" {
			t.Error("a link to a file in the real home passed")
		}
	}
	bad := []string{filepath.Join(Real(), "komando-testhome-no-such-folder", "x"), Real(), filepath.Join(Dir(), "..", "..", "x"), "relative/file"}
	if wd, err := os.Getwd(); err == nil {
		bad = append(bad, filepath.Join(wd, "testdata", "x"))
	}
	for _, p := range bad {
		f := &fakeTB{}
		if Path(f, p); f.failed == "" {
			t.Errorf("%s passed", p)
		}
	}
}
