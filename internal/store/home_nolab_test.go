//go:build !e2elab

package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A released komando is built without the e2elab tag, so it has no
// variable that names the account's home folder: home_lab.go is left out
// of a normal build, and nothing that builds a release names the tag.
// The lab's own komando does not stay on disk after a run.
func TestNoLabHomeInReleases(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{.GoFiles}} | {{.IgnoredGoFiles}}", ".").Output()
	if err != nil {
		t.Fatal("go list: ", err)
	}
	built, ignored, _ := strings.Cut(string(out), "|")
	if strings.Contains(built, "home_lab.go") || !strings.Contains(ignored, "home_lab.go") {
		t.Errorf("home_lab.go is in a normal build: %s", out)
	}
	root := filepath.Join("..", "..")
	// the release workflow never names the tag, and the Makefile's release
	// builds refuse a binary that knows the lab's variable (a tag that came
	// in through GOFLAGS)
	b, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil || strings.Contains(string(b), "e2elab") {
		t.Errorf("release.yml names the e2elab tag: %v", err)
	}
	b, err = os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil || strings.Contains(string(b), "e2elab") || strings.Count(string(b), "$(NOLAB)") < 2 {
		t.Errorf("the Makefile checks bins and dist with NOLAB, and names no e2elab tag: %v", err)
	}
	// the lab's komando is built outside the checkout and removed
	b, err = os.ReadFile(filepath.Join(root, "test", "e2e", "run.sh"))
	if err != nil || !strings.Contains(string(b), `-tags e2elab -o "$E2E_BIN"`) || !strings.Contains(string(b), `rm -rf "$E2E_BIN_DIR"`) {
		t.Errorf("test/e2e/run.sh builds the lab komando into a folder it removes: %v", err)
	}
}
