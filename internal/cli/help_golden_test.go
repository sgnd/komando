package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestHelpGolden pins the --help text of every command a person can see,
// in the order of the tree.
func TestHelpGolden(t *testing.T) {
	if testing.Short() || raceOn {
		t.Skip("runs --help of every command")
	}
	unixOnly(t, "the recording is made on Unix: default paths differ on Windows")
	var b strings.Builder
	for _, path := range visiblePaths(newRoot(tcl)) {
		args := append(append([]string{"-o", "text"}, path...), "--help")
		stdout, stderr, code := goldenRun(t, false, args)
		fmt.Fprintf(&b, "### komando %s\nexit %d\n--- stdout\n%s--- stderr\n%s", strings.Join(args[2:], " "), code, stdout, stderr)
	}
	matchGolden(t, "testdata/help_golden.txt", b.String())
}

// visiblePaths are the paths of every command a person can see, root
// first, in the order cobra lists them.
func visiblePaths(root *cobra.Command) [][]string {
	paths := [][]string{{}}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			if s.Hidden || strings.HasPrefix(s.Name(), "__") {
				continue
			}
			paths = append(paths, strings.Fields(strings.TrimPrefix(s.CommandPath(), root.Name()+" ")))
			walk(s)
		}
	}
	walk(root)
	return paths
}
