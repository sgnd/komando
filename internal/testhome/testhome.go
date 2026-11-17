// Package testhome keeps tests out of the real home folder.
//
// komando reads and writes under the home folder in many places: its own
// data in ~/.komando, and ~/.ssh, ~/.aws, ~/.kube and the like. A test
// that moves only komando's folder (KOMANDO_HOME) still has the real home
// behind os.UserHomeDir, and one such test once wrote over a person's
// private key. So every package whose code names a home folder starts its
// tests with Use, which gives the whole test binary a throwaway home.
package testhome

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// childEnv tells a test binary started by a test (a PTY child, a helper
// process) that its home is already the throwaway one.
const childEnv = "KOMANDO_TEST_HOME"

var real, dir string

// Real is the home folder the tests were started with. Nothing may be
// written there; tests use it only to say "not this one".
func Real() string { return real }

// Dir is the throwaway home folder ("" before Use).
func Dir() string { return dir }

// Use points HOME, USERPROFILE, APPDATA, LOCALAPPDATA and the XDG folders
// at one new, empty folder for the rest of the test binary, and returns
// the function that removes it. Call it first in TestMain:
//
//	func TestMain(m *testing.M) {
//		done := testhome.Use()
//		code := m.Run()
//		done()
//		os.Exit(code)
//	}
//
// A test binary that a test started itself keeps its parent's folder and
// removes nothing. The Go tool keeps the caches and the toolchain it had
// (they live under the real home), so a test may still run `go`.
func Use() (done func()) {
	real, _ = os.UserHomeDir()
	if d := os.Getenv(childEnv); d != "" {
		dir = d
		setHome(d)
		return func() {}
	}
	pinGo()
	d, err := os.MkdirTemp("", "komando-test-home-")
	if err != nil {
		panic("testhome: " + err.Error())
	}
	if r, err := filepath.EvalSymlinks(d); err == nil {
		d = r // macOS: /var is a link to /private/var
	}
	dir = d
	setHome(d)
	os.Setenv(childEnv, d)
	return func() { os.RemoveAll(d) }
}

func setHome(d string) {
	for k, v := range map[string]string{
		"HOME": d, "USERPROFILE": d,
		"APPDATA": filepath.Join(d, "AppData", "Roaming"), "LOCALAPPDATA": filepath.Join(d, "AppData", "Local"),
		"XDG_CONFIG_HOME": filepath.Join(d, ".config"), "XDG_DATA_HOME": filepath.Join(d, ".local", "share"),
		"XDG_CACHE_HOME": filepath.Join(d, ".cache"), "XDG_STATE_HOME": filepath.Join(d, ".local", "state"),
	} {
		os.Setenv(k, v)
	}
}

// pinGo writes into the environment what the Go tool would otherwise work
// out from the home folder: its caches and the toolchain in use.
func pinGo() {
	names := []string{"GOROOT", "GOCACHE", "GOMODCACHE", "GOPATH"}
	out, err := exec.Command("go", append([]string{"env"}, names...)...).Output()
	if err != nil {
		return // no Go tool here (a test binary run by itself): nothing to keep
	}
	vals := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), "\r\n", "\n"), "\n")
	if len(vals) != len(names) {
		return
	}
	for i, n := range names {
		if vals[i] != "" {
			os.Setenv(n, vals[i])
		}
	}
	if vals[0] != "" {
		os.Setenv("PATH", filepath.Join(vals[0], "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
}

// TB is the part of testing.TB that Path needs.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// Path returns p when it lies in the throwaway home or in the system's
// temp folder (t.TempDir), and fails the test otherwise. A test that
// writes to a path built from the home folder passes the path through
// it, so a test started without Use cannot reach the real home.
func Path(t TB, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("testhome: %v", err)
		return p
	}
	roots := []string{os.TempDir()}
	if dir != "" {
		roots = append(roots, dir)
	}
	for _, r := range roots {
		for _, root := range []string{r, evalOr(r)} {
			for _, a := range []string{abs, evalOr(filepath.Dir(abs))} {
				if rel, err := filepath.Rel(root, a); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
					return p
				}
			}
		}
	}
	t.Fatalf("testhome: %s is outside the throwaway home (%s) and the temp folder: a test must not write there", p, dir)
	return p
}

func evalOr(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
