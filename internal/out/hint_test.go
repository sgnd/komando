package out

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every error tells the reader what to do next (docs/design/ux.md, section
// 5): an Errf with an empty hint is a bug.
func TestEveryErrfHasHint(t *testing.T) {
	empty := regexp.MustCompile(`Errf\([^,]+,\s*"[A-Z_]+",\s*"",`)
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(b), "\n") {
				if empty.MatchString(line) {
					t.Errorf("%s:%d: error without a hint: %s", p, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
