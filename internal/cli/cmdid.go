package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

// Every command has a stable ID: its dotted path at the time it was added
// (fs.ls, secret.get, host.mv). The ID never changes, even when the command
// gets a new name: the success and error envelopes, the audit log and every
// table keyed by command (commandKinds, personalCmds, localReads,
// leavesHome, the ssh-gate tables, the secret.get mask line) use it, so a
// rename cannot let a command slip past a check by its new name
// (docs/design/command-standard.md, S-1.6).
//
// A command renamed later keeps its ID with withID; a thin wrapper that runs
// another command (an alias that needs its own argument rule) carries the
// ID of the command it runs.

// cmdIDNote is the annotation that holds a command's ID.
const cmdIDNote = "komando.id"

// withID gives c the ID id. Use it when renaming a command (the ID stays
// the old dotted path) and for a wrapper command (the ID of the command it
// runs).
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
