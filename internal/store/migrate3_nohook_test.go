package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The migration hook exists only in a build with the migratehook tag; the
// build every workflow makes has no such symbol (Audit M10).
func TestReleaseHasNoMigrateHook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds this package twice")
	}
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	dir := t.TempDir()
	for _, tc := range []struct {
		tags string
		want bool
	}{{"", false}, {"migratehook", true}} {
		archive := filepath.Join(dir, "store-"+tc.tags+".a")
		args := []string{"build", "-o", archive}
		if tc.tags != "" {
			args = append(args, "-tags", tc.tags)
		}
		build := exec.Command(gobin, append(args, ".")...)
		build.Env = append(os.Environ(), "GOFLAGS=")
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, b)
		}
		nm, err := exec.Command(gobin, "tool", "nm", archive).Output()
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(nm), "migrateHook"); has != tc.want {
			t.Errorf("tags %q: migrateHook in the build is %v, want %v", tc.tags, has, tc.want)
		}
	}
	wf, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(wf) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, f := range wf {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "migratehook") {
			t.Errorf("%s sets the migratehook tag", f)
		}
	}
}
