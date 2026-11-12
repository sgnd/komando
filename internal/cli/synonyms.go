package cli

import (
	"slices"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// A synonym is a second name that is permanent and silent (S-1.7). Most
// are cobra Aliases on the command. One that needs its own argument rule
// (group show GROUP runs group list GROUP, which also works without GROUP)
// is a hidden wrapper command (S-1.8): it shares every flag of the command
// it runs and carries that command's ID, so every check, gate and mask
// keys it the same way.

// synonymNote names, on a hidden wrapper, the command it stands for, so
// `komando schema` can show that one (S-9.8).
const synonymNote = "komando.synonym-of"

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
	"group": {"groups"}, "secret": {"secrets"}, "key": {"keys"}, "recipe": {"recipes"},
	"policy": {"policies"}, "job": {"jobs"}, "tunnel": {"tunnels"}, "fs": {"files"},
	"svc": {"service", "services"}, "pkg": {"package", "packages"}, "user": {"users"},
	"cron": {"crons"}, "docker": {"container", "containers"}, "net": {"network"},
	"cert": {"certs"}, "db": {"dbs", "database", "databases"}, "cache": {"caches"},
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

// synonymWrapper is a hidden command `use` that runs of with its own
// argument rule. id is of's ID and now its path, as `komando now`.
func synonymWrapper(of *cobra.Command, use, id, now string, args cobra.PositionalArgs) *cobra.Command {
	c := &cobra.Command{
		Use:    use,
		Short:  "Same as `komando " + now + "`",
		Hidden: true,
		Args:   args,
		RunE: func(cmd *cobra.Command, a []string) error {
			return of.RunE(cmd, a)
		},
	}
	c.Flags().AddFlagSet(of.Flags())
	withID(c, id)
	c.Annotations[synonymNote] = now
	return c
}

// tunnelShowCmd is `tunnel show TUNNEL`: tunnel list for one tunnel.
func tunnelShowCmd() *cobra.Command {
	c := &cobra.Command{
		Use:    "show TUNNEL",
		Short:  "Same as `komando tunnel list`, for one tunnel",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, ok := st.Tunnels[args[0]]
			if !ok {
				return out.NotFound("tunnel", args[0])
			}
			row := tunnelRow{Tunnel: t, Alive: tunnelAlive(t), Listen: tunnelListen(t)}
			out.P.Print("tunnel.list", tunnelList{Count: 1, Tunnels: []tunnelRow{row}}, nil)
			return nil
		},
	}
	withID(c, "tunnel.list")
	c.Annotations[synonymNote] = "tunnel list"
	return c
}

// recipeShowCmd is `recipe show NAME`: recipe list for one recipe.
func recipeShowCmd() *cobra.Command {
	c := &cobra.Command{
		Use:    "show NAME",
		Short:  "Same as `komando recipe list`, for one recipe",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			r, ok := findRecipe(st, args[0])
			if !ok {
				return recipeNotFound(args[0])
			}
			out.P.Print("recipe.list", recipeList{Count: 1, Recipes: []recipeRow{r}}, nil)
			return nil
		},
	}
	withID(c, "recipe.list")
	c.Annotations[synonymNote] = "recipe list"
	return c
}

// forwardCmd is the old top-level `forward`, which was another name for
// `tunnel` and read like `cluster forward`. It is retired: each use is
// noted (meta.deprecated, and stderr at a terminal) and runs the tunnel
// command with its ID (C-V17).
func forwardCmd() *cobra.Command {
	c := withID(&cobra.Command{Use: "forward"}, "tunnel")
	markOldName(c, "tunnel")
	for _, sub := range []*cobra.Command{tunnelStartCmd(), tunnelListCmd(), tunnelStopCmd()} {
		now := "tunnel " + sub.Name()
		c.AddCommand(oldName(withID(sub, "tunnel."+sub.Name()), now))
	}
	return c
}
