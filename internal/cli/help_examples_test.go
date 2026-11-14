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
	root := newRoot(treeCall()) // a tree of its own: the examples' flags are not tcl's
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

// `komando svc` alone (and the other server groups) shows the usual
// journey as examples, and the times in them are written as komando takes
// them everywhere (30m, not -30m).
func TestOpsGroupsShowAJourney(t *testing.T) {
	root := newRoot(tcl)
	for _, g := range []string{"svc", "pkg", "user", "docker", "cron", "net", "cert", "recipe"} {
		c, _, err := root.Find([]string{g})
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(c.Example, "komando "+g+" "); n < 2 {
			t.Errorf("komando %s: %d examples of its own commands", g, n)
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if strings.Contains(c.Example, "--since -") || strings.Contains(c.Example, "--until -") {
			t.Errorf("%s: example with a - in front of the time: %q", c.CommandPath(), c.Example)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
