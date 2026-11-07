package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// commonGlobals are the global flags a sub-command's --help shows; the
// other global flags are in `komando --help` (ux.md, anti-slop checklist).
var commonGlobals = []string{"dry-run", "output", "timeout", "yes"}

func init() {
	cobra.AddTemplateFunc("commonGlobals", func(c *cobra.Command) string {
		fs := pflag.NewFlagSet("", pflag.ContinueOnError)
		c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
			for _, n := range commonGlobals {
				if f.Name == n {
					fs.AddFlag(f)
				}
			}
		})
		return strings.TrimRight(fs.FlagUsages(), " \n")
	})
}

// useShortGlobals makes every sub-command's --help list the few global
// flags that matter there, instead of all of them on every page.
func useShortGlobals(root *cobra.Command) {
	t := strings.Replace(root.UsageTemplate(),
		"Global Flags:\n{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}",
		"Global Flags (all of them: komando --help):\n{{commonGlobals .}}", 1)
	root.SetUsageTemplate(t)
}
