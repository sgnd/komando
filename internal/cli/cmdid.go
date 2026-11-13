package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// Every command has an ID: its dotted path (fs.list, secret.show,
// host.rename). The success and error envelopes, the audit log and every
// table keyed by command (commandKinds, personalCmds, localReads,
// leavesHome, the ssh-gate tables, the secret.show mask line) use it, and
// TestTablesKeyedByID checks that each key is a command's ID, so a rename
// that forgets a table fails there instead of slipping past a check
// (docs/design/command-standard.md, S-1.6). A rename changes the ID with
// the path, in the same commit as every table and testdata/command_ids.txt
// (komando is used internally only).
//
// A thin wrapper that runs another command (a synonym that needs its own
// argument rule) carries the ID of the command it runs (withID).

// cmdIDNote is the annotation that holds a command's ID.
const cmdIDNote = "komando.id"

// withID gives c the ID id: for a wrapper command, the ID of the command
// it runs.
func withID(c *cobra.Command, id string) *cobra.Command {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[cmdIDNote] = id
	return c
}

// stampIDs writes each command's ID into its annotations: the one withID
// gave it, else its dotted path.
func stampIDs(c *cobra.Command) {
	withID(c, cmdID(c))
	for _, s := range c.Commands() {
		stampIDs(s)
	}
}

// cmdID is c's ID: the withID annotation, else its dotted path without
// "komando" ("komando" for the root itself).
func cmdID(c *cobra.Command) string {
	if id := c.Annotations[cmdIDNote]; id != "" {
		return id
	}
	p := strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "komando"))
	if p == "" {
		return "komando"
	}
	return strings.ReplaceAll(p, " ", ".")
}

// idKey is c's ID with spaces for dots, as commandKinds and personalCmds
// write it ("cache keys").
func idKey(c *cobra.Command) string {
	return strings.ReplaceAll(cmdID(c), ".", " ")
}
