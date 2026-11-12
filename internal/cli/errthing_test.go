package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// TestSharedCodes: every error.thing the source sets (About("x"),
// Thing: "x", out's sharedThings) is in sharedCodes, the split list for
// contract 2 (S-8.3, C-E02), so the docs name every value agents can see.
func TestSharedCodes(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range sharedCodes {
		for _, th := range c.Things {
			listed[th] = true
		}
	}
	for _, k := range []string{"host", "conn", "vpn", "job", "key", "recipe", "secret", "tunnel", "group"} {
		if th := out.NotFound(k, "x").Thing; th != "" && !listed[th] {
			t.Errorf("out.NotFound(%q) sets error.thing %q, which sharedCodes does not list", k, th)
		}
	}
	thing := regexp.MustCompile(`About\("([a-z0-9_]+)"\)|Thing: +"([a-z0-9_]+)"`)
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range thing.FindAllStringSubmatch(string(b), -1) {
			th := m[1] + m[2]
			if th == "" {
				continue
			}
			if !listed[th] {
				t.Errorf("%s sets error.thing %q, which sharedCodes does not list", path, th)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sharedCodes {
		if !slices.ContainsFunc(errorCodes, func(e errorCode) bool { return e.Code == c.Code }) {
			t.Errorf("sharedCodes lists %s, which the catalog does not have", c.Code)
		}
	}
}
