package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

var flagInText = regexp.MustCompile(`--[a-z][a-z0-9]*(?:-[a-z0-9]+)*`)

// Every --flag a copy hint or error names is a flag of `komando copy` (or
// one every command has), so a removed flag such as --to never comes back
// in a hint. --old belongs to `komando fs replace`, named in the same text.
func TestCopyHintsNameOnlyFlagsOfCopy(t *testing.T) {
	c, _, err := newRoot(tcl).Find([]string{"copy"})
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{"--old": true}
	add := func(f *pflag.Flag) { known["--"+f.Name] = true }
	c.Flags().VisitAll(add)
	c.InheritedFlags().VisitAll(add)
	files, _ := filepath.Glob("copy*.go")
	files = append(files, "storage_download.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			for _, f := range flagInText.FindAllString(line, -1) {
				if !known[f] {
					t.Errorf("%s:%d names %s, which copy does not have", name, i+1, f)
				}
			}
		}
	}
}
