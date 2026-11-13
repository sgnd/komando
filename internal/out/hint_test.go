package out

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every error tells the reader what to do next (docs/design/command-standard.md,
// S-8.5): an Errf with an empty hint is a bug.
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

// An error whose code gives no hint still has one in the output: the
// general hint for its exit code. A hint of its own stays as written.
func TestErrorJSONAlwaysHasHint(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Format: "json", W: &buf}
	p.Fail("cluster.run", &Error{Code: "FAILED", Message: "m", Exit: ExitTimeout})
	if !strings.Contains(buf.String(), `"hint":"`+DefaultHint(ExitTimeout)+`"`) {
		t.Errorf("no default hint: %s", buf.String())
	}
	buf.Reset()
	p.Print("x", map[string]any{"results": []*Error{{Code: "X_Y", Message: "m", Hint: "store it with `komando secret set NAME < ca.crt`"}}}, nil)
	if !strings.Contains(buf.String(), "NAME < ca.crt") {
		t.Errorf("own hint changed: %s", buf.String())
	}
	for exit := ExitOK; exit <= ExitConflict; exit++ {
		if DefaultHint(exit) == "" {
			t.Errorf("exit %d has no default hint", exit)
		}
	}
}
