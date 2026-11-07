package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestExamplesParse runs every --help example through the command parser:
// an example that names a command or flag komando does not have teaches
// people something wrong.
func TestExamplesParse(t *testing.T) {
	root := newRoot()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, line := range strings.Split(c.Example, "\n") {
			line = strings.TrimSpace(line)
			if i := strings.Index(line, "  #"); i > 0 {
				line = strings.TrimSpace(line[:i])
			}
			if !strings.HasPrefix(line, "komando ") || strings.ContainsAny(line, "|<>$`;&") {
				continue // a pipe or shell syntax: not one komando command
			}
			args := shellWords(line)[1:]
			cmd, rest, err := root.Find(args)
			if err != nil {
				t.Errorf("%s: example %q: %v", c.CommandPath(), line, err)
				continue
			}
			if err := cmd.ParseFlags(rest); err != nil {
				t.Errorf("%s: example %q: %v", c.CommandPath(), line, err)
			}
			cmd.Flags().VisitAll(func(f *pflag.Flag) { _ = f.Value.Set(f.DefValue); f.Changed = false })
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
