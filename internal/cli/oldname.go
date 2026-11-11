package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// oldNameNote marks a command as an old name kept for one release; the
// audit-log check still runs for it, as for the new name.
const oldNameNote = "komando.old-name"

// oldName hides c, an old name that keeps working for one release, and
// makes it say the new name on stderr each time it runs (docs/design/ux.md,
// section 10). c must already call the same code as `komando now`.
func oldName(c *cobra.Command, now string) *cobra.Command {
	markOldName(c, now)
	run := c.RunE
	c.RunE = func(cmd *cobra.Command, args []string) error {
		sayOldName(cmd)
		return run(cmd, args)
	}
	return c
}

// backgroundCmd reports whether cmd is hidden because komando itself runs
// it (tunnel serve, vpn serve, the agent guard), not an old name a person or
// agent types: those get every check of the new name.
func backgroundCmd(cmd *cobra.Command) bool {
	return cmd.Hidden && cmd.Annotations[oldNameNote] == ""
}

// markOldName hides c and names the command that does it now.
func markOldName(c *cobra.Command, now string) {
	c.Hidden = true
	c.Short = "Old name of `komando " + now + "`"
	c.Long, c.Example = "", ""
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[oldNameNote] = now
}

// sayOldName prints the one-line note of an old name on stderr.
func sayOldName(cmd *cobra.Command) {
	if now := cmd.Annotations[oldNameNote]; now != "" {
		fmt.Fprintf(os.Stderr, "note: use `komando %s` now; `%s` goes away in the next release\n", now, cmd.CommandPath())
	}
}

// droppedNames are old names that are gone, by the command that does it now
// (its path under komando): typing one suggests that command.
var droppedNames = map[string][]string{
	"recipe":    {"ops", "snippet", "snippets", "diag"},
	"facts":     {"inspect"},
	"svc":       {"systemd"},
	"policy rm": {"allow"},
}

// suggestDroppedNames lets each command that took over a dropped name
// suggest itself for it (usageErr then names only that command).
func suggestDroppedNames(root *cobra.Command) {
	for path, old := range droppedNames {
		if c, _, err := root.Find(strings.Fields(path)); err == nil && c != root {
			c.SuggestFor = append(c.SuggestFor, old...)
		}
	}
}
