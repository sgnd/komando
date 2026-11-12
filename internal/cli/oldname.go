package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
)

// Old spellings come in two kinds (docs/design/ux.md, section 10):
//
//   - synonyms (ls, mv, get, plural nouns, server, database): cobra
//     Aliases on the command itself. They are permanent and print nothing;
//   - retired names (an old command name such as `script`, an old flag, an
//     old argument shape): they keep working, and each use goes through
//     retiredName, the only place that notes one.

// oldNameNote marks a command as an old name; the audit-log check still
// runs for it, as for the new name.
const oldNameNote = "komando.old-name"

// retiredName notes that the command used a retired spelling: additive
// meta.deprecated {used, now} in JSON, and one line on stderr only when
// stderr is a terminal, so `2>&1 | jq` and agents reading stderr see no
// new text.
func retiredName(used, now string) {
	out.P.UsedRetired(used, now)
	if term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintf(os.Stderr, "komando: `%s` is an old spelling that still works; use `%s` now\n", used, now)
	}
}

// oldName hides c, an old name that keeps working, and notes the new name
// (retiredName) each time it runs. c must already call the same code as
// `komando now`.
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
// it (tunnel serve, vpn serve, the agent guard), not an old name or a
// synonym (cluster info, tunnel show) a person or agent types: those get
// every check of the command they name.
func backgroundCmd(cmd *cobra.Command) bool {
	return cmd.Hidden && cmd.Annotations[oldNameNote] == "" && cmd.Annotations[synonymNote] == ""
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

// sayOldName notes the old name cmd was typed by (retiredName).
func sayOldName(cmd *cobra.Command) {
	if now := cmd.Annotations[oldNameNote]; now != "" {
		retiredName(cmd.CommandPath(), "komando "+now)
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
