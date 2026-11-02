package cli

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestConventions checks the naming rules of docs/design/ux.md on every
// command, so a new command cannot drift from them.
func TestConventions(t *testing.T) {
	// one meaning per short flag
	shorts := map[string]string{"n": "limit", "r": "recursive", "g": "group", "t": "tag", "s": "sudo", "o": "output", "y": "yes", "f": "follow"}
	// renamed flags; the old names may only exist as deprecated aliases
	retired := []string{"force", "param", "lines", "number", "host", "mutating"}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if slices.Contains([]string{"remove", "delete", "del"}, c.Name()) {
			t.Errorf("%s: name it rm (remove, delete and del are aliases)", path)
		}
		if c.Name() == "rm" && !slices.Equal(c.Aliases, rmAliases) {
			t.Errorf("%s: aliases %v, want %v", path, c.Aliases, rmAliases)
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			// -f is --file only where the native tool means that too (psql -f, docker compose -f)
			fileOK := f.Shorthand == "f" && f.Name == "file" && slices.Contains([]string{"komando db query", "komando docker compose"}, path)
			if want, ok := shorts[f.Shorthand]; ok && f.Name != want && !fileOK {
				t.Errorf("%s --%s: -%s is reserved for --%s", path, f.Name, f.Shorthand, want)
			}
			if slices.Contains(retired, f.Name) && f.Deprecated == "" {
				t.Errorf("%s --%s: renamed flag must be a deprecated alias (see aliasFlag)", path, f.Name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot())
}
