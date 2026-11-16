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
func TestNoLabHomeInReleases(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{.GoFiles}} | {{.IgnoredGoFiles}}", ".").Output()
	if err != nil {
		t.Skip("go list: ", err)
	}
	built, ignored, _ := strings.Cut(string(out), "|")
	if strings.Contains(built, "home_lab.go") || !strings.Contains(ignored, "home_lab.go") {
		t.Errorf("home_lab.go is in a normal build: %s", out)
	}
	root := filepath.Join("..", "..")
	files := []string{"Makefile", filepath.Join(".github", "workflows", "release.yml"), filepath.Join(".github", "workflows", "ci.yml")}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "e2elab") {
			t.Errorf("%s names the e2elab tag: only test/e2e/run.sh builds a lab komando", f)
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "test", "e2e", "run.sh"))
	if err != nil || !strings.Contains(string(b), "-tags e2elab -o bin/komando-e2e") {
		t.Errorf("test/e2e/run.sh builds the lab komando into bin/komando-e2e: %v", err)
	}
}
