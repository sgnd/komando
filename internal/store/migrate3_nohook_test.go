package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The migration hook exists only in a build with the migratehook tag; the
// release build has no such symbol (Audit M10). The release (release.yml
// and the Makefile it runs) never names the tag. Another workflow may name
// it only in a `go test` step, whose test program is never shipped: CI
// runs the kill-between-steps test that way (Audit E1 M3).
func TestReleaseHasNoMigrateHook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds this package twice")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
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
	root := filepath.Join("..", "..")
	wf, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil || len(wf) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	release := map[string]bool{filepath.Join(root, ".github", "workflows", "release.yml"): true, filepath.Join(root, "Makefile"): true}
	tested := 0
	for _, f := range append(wf, filepath.Join(root, "Makefile")) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			code := strings.TrimSpace(line)
			if !strings.Contains(code, "migratehook") || strings.HasPrefix(code, "#") {
				continue
			}
			switch {
			case release[f]:
				t.Errorf("%s:%d: the release build names the migratehook tag", f, i+1)
			case !strings.Contains(code, "go test ") || strings.Contains(code, "go build") || strings.Contains(code, "go install") || strings.Contains(code, "make "):
				t.Errorf("%s:%d: the migratehook tag outside a `go test` step: %s", f, i+1, code)
			default:
				tested++
			}
		}
	}
	if tested == 0 {
		t.Error("no workflow runs the kill-between-steps test with the migratehook tag")
	}
}
