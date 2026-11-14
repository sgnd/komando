package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestHelpReadsWell checks what `--help` shows people: every runnable
// command has a one-line summary, and no flag's value placeholder comes from
// a backticked phrase in its usage (cobra turns "`komando key`" into the
// placeholder, so help would print `--key komando key`).
func TestHelpReadsWell(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden {
			return
		}
		if c.Runnable() && strings.TrimSpace(c.Short) == "" {
			t.Errorf("%s: no one-line summary (Short)", c.CommandPath())
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden {
				return
			}
			if name, _ := pflag.UnquoteUsage(f); strings.Contains(name, " ") {
				t.Errorf("%s --%s: help shows the placeholder %q (a backticked phrase in the usage); drop the backticks", c.CommandPath(), f.Name, name)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot(tcl))
}
