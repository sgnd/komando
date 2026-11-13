package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `key mv` and `group mv` rename one key or one group with the engine of
// `komando rename` (rename.go): every reference follows, in one step.

// mvFromRename turns the engine's result into what the mv commands print.
func mvFromRename(kind, from, to string, r renameResult) mvResult {
	res := mvResult{Kind: kind, From: from, To: to, Action: r.Action, Updated: []string{}, Warnings: r.Warnings}
	for _, u := range r.Updated {
		res.Updated = append(res.Updated, u.String())
	}
	for _, m := range r.Moved {
		res.Moved = append(res.Moved, m.From+" -> "+m.To)
	}
	return res
}

func keyMvCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rename OLD NEW",
		Aliases: []string{"mv"}, // a plain synonym
		Short:   "Rename a key, and every server that uses it",
		Long: `Gives a key in komando's key list a new name; the servers that use it follow. A
key komando made (key gen) lives in the sealed store, so no file moves; a key
added from elsewhere (key add) stays where it is. Public keys already installed on servers keep their comment: they
still work, since the key itself does not change.`,
		Example: `  komando key rename deploy deploy-2026
  komando key rename old-ci ci --dry-run`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, to := args[0], args[1]
			r, err := renameTx(func(s *store.State) (renameSet, renameOpts, error) {
				k, err := findKey(s, from)
				if err != nil {
					return nil, renameOpts{}, err
				}
				if k.Name == to {
					return renameSet{}, renameOpts{}, nil
				}
				if err := validName("key", to); err != nil {
					return nil, renameOpts{}, err
				}
				if s.Keys[to] != nil {
					return nil, renameOpts{}, keyExists(to)
				}
				return renameSet{"key": {from: to}}, renameOpts{}, nil
			})
			if err != nil {
				return err
			}
			res := mvFromRename("key", from, to, r)
			if res.Action == "renamed" {
				audit(nil, "key.rename", nil, "", true, map[string]any{"from": from, "to": to, "updated": len(res.Updated), "moved": res.Moved})
			}
			out.P.Print("key.rename", res, nil)
			return nil
		},
	}
}

func groupMvCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rename OLD NEW",
		Aliases: []string{"mv"}, // a plain synonym
		Short:   "Rename a group on every server, conn and VPN in it",
		Long: `Gives a group a new name on every member. OLD matches in any case, like
@OLD. When NEW is a group already, nothing changes (GROUP_EXISTS): to merge
two groups, add the members with ` + "`komando group add NEW @OLD`" + ` and then run
` + "`komando group rm OLD`" + `. When a protected server or conn is in the group,
renaming it needs --yes, once for all of them.`,
		Example: `  komando group rename web frontend
  komando group rename prod production --dry-run`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, to := strings.TrimPrefix(args[0], "@"), strings.TrimPrefix(args[1], "@")
			what := "renaming group " + from + " to " + to
			r, err := renameTx(func(s *store.State) (renameSet, renameOpts, error) {
				var spellings []string // Web and web are one group
				for _, gr := range mapKeys(allGroups(s).Groups) {
					if strings.EqualFold(gr, from) {
						spellings = append(spellings, gr)
					}
				}
				if len(spellings) == 0 {
					return nil, renameOpts{}, groupNotFound(s, from)
				}
				if err := validLabelName("group", to); err != nil {
					return nil, renameOpts{}, err
				}
				if !strings.EqualFold(from, to) {
					for _, gr := range mapKeys(allGroups(s).Groups) {
						if strings.EqualFold(gr, to) {
							return nil, renameOpts{}, out.Errf(out.ExitConflict, "GROUP_EXISTS",
								"pick another name; to merge them, run `komando group add "+to+" @"+from+"` and then `komando group rm "+from+"`",
								"group %q exists", gr)
						}
					}
				}
				set := renameSet{}
				for _, sp := range spellings {
					if sp != to {
						if set["group"] == nil {
							set["group"] = map[string]string{}
						}
						set["group"][sp] = to
					}
				}
				return set, renameOpts{guard: func(prot []string) error { return guardRenameProtected(what, prot) }}, nil
			})
			if err != nil {
				return err
			}
			res := mvFromRename("group", from, to, r)
			if res.Action == "renamed" {
				audit(nil, "group.rename", nil, "", true, map[string]any{"from": from, "to": to, "updated": len(res.Updated)})
			}
			out.P.Print("group.rename", res, nil)
			return nil
		},
	}
}
