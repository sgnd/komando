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
	// old flag names that were renamed and then removed; they must not come back
	retired := []string{"force", "param", "lines", "number", "host", "mutating", "jump", "rename", "wait-timeout"}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := c.CommandPath()
		if slices.Contains([]string{"remove", "delete", "del"}, c.Name()) {
			t.Errorf("%s: name it rm (remove, delete and del are aliases)", path)
		}
		if c.Name() == "rm" && !slices.Equal(c.Aliases, rmAliases) {
			t.Errorf("%s: aliases %v, want %v", path, c.Aliases, rmAliases)
		}
		if other, ok := map[string]string{"list": "ls", "ls": "list"}[c.Name()]; ok {
			if !slices.Contains(c.Aliases, other) {
				t.Errorf("%s: aliases %v, want %s too", path, c.Aliases, other)
			}
			if sib, _, err := c.Parent().Find([]string{other}); err == nil && sib != c && sib != c.Parent() {
				t.Errorf("%s: %s is another command here", path, other)
			}
		}
		// every command people run shows one real example (ux.md, section 10)
		if c.Runnable() && !c.HasSubCommands() && !c.Hidden && c.Example == "" && c.Name() != "help" && c.Parent().Name() != "completion" {
			t.Errorf("%s: no example; set Example or add one to examples (examples.go)", path)
		}
		if _, ok := examples[path]; ok && c.Example != examples[path] {
			t.Errorf("%s: has its own Example; remove it from examples.go", path)
		}
		// command lists fit 80 columns: `komando --help` puts a top-level
		// Short at column 15, a sub-command's a little further right
		if limit := map[bool]int{true: 64, false: 80}[c.Parent() == c.Root()]; len(c.Short) > limit {
			t.Errorf("%s: Short is %d characters, over %d; move the detail to Long", path, len(c.Short), limit)
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			// -f is --file only where the native tool means that too (psql -f, docker compose -f)
			fileOK := f.Shorthand == "f" && f.Name == "file" && slices.Contains([]string{"komando db query", "komando docker compose"}, path)
			if want, ok := shorts[f.Shorthand]; ok && f.Name != want && !fileOK {
				t.Errorf("%s --%s: -%s is reserved for --%s", path, f.Name, f.Shorthand, want)
			}
			if slices.Contains(retired, f.Name) {
				t.Errorf("%s --%s: retired flag name; use the new name (see CHANGELOG, Removed)", path, f.Name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot())
}
