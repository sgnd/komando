package cli

import (
	"slices"

	"github.com/spf13/cobra"
)

// A synonym is a second name that is permanent and silent (S-1.7): a cobra
// Alias on the command, so it is the same command for every check, gate and
// mask.

// backgroundCmd reports whether cmd is hidden because komando itself runs
// it (tunnel serve, vpn serve, the agent guard).
func backgroundCmd(cmd *cobra.Command) bool {
	return cmd.Hidden
}

// addAliases adds permanent synonyms to c.
func addAliases(c *cobra.Command, names ...string) *cobra.Command {
	for _, n := range names {
		if !slices.Contains(c.Aliases, n) {
			c.Aliases = append(c.Aliases, n)
		}
	}
	return c
}

// nounAliases are the plural of each noun and the word help text uses for
// it (S-2.1): `komando servers`, `komando databases` and `komando files`
// find the command people mean.
var nounAliases = map[string][]string{
	"host": {"hosts", "server", "servers"}, "conn": {"conns"}, "vpn": {"vpns"},
	"group": {"groups"}, "snippet": {"snippets"},
	"policy": {"policies"}, "fs": {"files"},
	"pkg": {"package", "packages"}, "docker": {"container", "containers"},
	"db": {"dbs"}, "database": {"databases"}, "cache": {"caches"},
	"queue": {"queues"}, "cluster": {"clusters"}, "registry": {"registries"},
}

// addNounAliases gives each top-level noun its nounAliases.
func addNounAliases(root *cobra.Command) {
	for _, c := range root.Commands() {
		if a, ok := nounAliases[c.Name()]; ok {
			addAliases(c, a...)
		}
	}
}
