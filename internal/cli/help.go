package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// commonGlobals are the global flags a sub-command's --help shows; the
// other global flags are in `komando --help` (ux.md, anti-slop checklist).
var commonGlobals = []string{"dry-run", "output", "timeout", "yes"}

// ownFlags are a command's flags, its own and the ones a parent gives all
// its sub-commands (`cron --user` for `cron list`): the flags of this
// command, which --help and `komando schema` list. Global flags are not.
func ownFlags(c *cobra.Command) *pflag.FlagSet {
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)
	c.LocalFlags().VisitAll(func(f *pflag.Flag) { fs.AddFlag(f) })
	root := c.Root()
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		if root.PersistentFlags().Lookup(f.Name) == nil && fs.Lookup(f.Name) == nil {
			fs.AddFlag(f)
		}
	})
	return fs
}

func init() {
	cobra.AddTemplateFunc("ownFlagUsages", func(c *cobra.Command) string {
		if c.HasParent() {
			return strings.TrimRight(ownFlags(c).FlagUsages(), " \n")
		}
		return rootFlagUsages(c)
	})
	cobra.AddTemplateFunc("hasOwnFlags", func(c *cobra.Command) bool {
		has := false
		ownFlags(c).VisitAll(func(f *pflag.Flag) { has = has || !f.Hidden })
		return has
	})
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
	// a parent's flags for all its sub-commands are this command's own
	t = strings.Replace(t, "{{if .HasAvailableLocalFlags}}", "{{if hasOwnFlags .}}", 1)
	t = strings.Replace(t, "{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}", "{{ownFlagUsages .}}", 1)
	root.SetUsageTemplate(t)
	root.SetHelpTemplate(rootHelpTemplate)
}

// safetyOverrides are the root flags that skip a safety check. `komando
// --help` lists them last, under their own heading, so nobody adds one by
// habit.
var safetyOverrides = []string{"yes", "allow-dangerous", "reveal"}

// rootFlagUsages is the Flags block of `komando --help`: the everyday flags,
// then the safety overrides.
func rootFlagUsages(root *cobra.Command) string {
	common := pflag.NewFlagSet("", pflag.ContinueOnError)
	safety := pflag.NewFlagSet("", pflag.ContinueOnError)
	ownFlags(root).VisitAll(func(f *pflag.Flag) {
		for _, n := range safetyOverrides {
			if f.Name == n {
				safety.AddFlag(f)
				return
			}
		}
		common.AddFlag(f)
	})
	b := strings.TrimRight(common.FlagUsages(), " \n")
	if s := strings.TrimRight(safety.FlagUsages(), " \n"); s != "" {
		b += "\n\nSafety overrides (ask a person first):\n" + s
	}
	return b
}

// helpNotes is the annotation that holds the details of a command, which
// --help prints after the flags so the first lines say what it is for.
const helpNotes = "help_notes"

// rootHelpTemplate is cobra's help template plus, for `komando --help`
// only, the notes for scripts below the command list.
const rootHelpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}{{with index .Annotations "help_notes"}}
{{.}}
{{end}}{{if not .HasParent}}
` + rootScriptNotes + `
{{end}}`
