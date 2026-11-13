package cli

import (
	"slices"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/spf13/cobra"
)

// host rm, and what it checks first.

// keptHostKeys lists the removed servers (name -> address) whose key is
// still pinned and whose address no server left in the inventory uses.
// host rm never removes a pin by itself: rm plus add would then get past a
// HOSTKEY_MISMATCH without a person's yes.
func keptHostKeys(s *store.State, gone map[string]string) []string {
	used := map[string]bool{}
	for _, h := range s.Hosts {
		used[trustAddr(h)] = true
	}
	var kept []string
	for n, addr := range gone {
		if !used[addr] && countPinned(addr) > 0 {
			kept = append(kept, n)
		}
	}
	sort.Strings(kept)
	return kept
}

// hostsInUse stops host rm when a server or conn left in the inventory
// reaches one of names through --via. It names every such user at once, so
// one round of edits clears them all. Servers removed in the same command
// (batch) do not count.
func hostsInUse(s *store.State, names []string, batch map[string]bool) error {
	var users, fixes []string
	for _, n := range names {
		for _, o := range s.SortedHosts() {
			if !batch[o.Name] && slices.Contains(viaChain(o.Via), n) {
				users = append(users, "server "+o.Name+viaNote(names, n))
				fixes = append(fixes, "`komando host edit "+o.Name+" --unset via`")
			}
		}
		for _, c := range s.SortedConns() {
			if slices.Contains(viaChain(c.Via), n) {
				users = append(users, "conn "+c.Name+viaNote(names, n))
				fixes = append(fixes, "`komando conn edit "+c.Name+" --unset via`")
			}
		}
	}
	if len(users) == 0 {
		return nil
	}
	hint := "change them first: " + strings.Join(fixes, ", ") + " (or --via OTHER), or remove them in the same command"
	if len(names) == 1 {
		return out.Errf(out.ExitConflict, "HOST_IN_USE", hint, "server %q is on the --via path of %s", names[0], strings.Join(users, ", "))
	}
	return out.Errf(out.ExitConflict, "HOST_IN_USE", hint, "these servers are on a --via path: %s", strings.Join(users, ", "))
}

// viaNote names the removed server a user goes through, when several are
// removed at once.
func viaNote(names []string, n string) string {
	if len(names) == 1 {
		return ""
	}
	return " (via " + n + ")"
}

func hostRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm TARGET...",
		Short: "Remove servers (from komando only)",
		Example: `  komando host rm web3
  komando host rm @old --dry-run     # what a selector would remove
  komando host rm 'tmp-*'`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names, kept, unused []string
			err := store.Update(func(s *store.State) error {
				var prot []string
				batch := map[string]bool{}
				hosts, err := pickHosts(s, args)
				if err != nil {
					return err
				}
				for _, h := range hosts {
					names = append(names, h.Name)
					batch[h.Name] = true
					if h.Protected {
						prot = append(prot, h.Name)
					}
				}
				if err := hostsInUse(s, names, batch); err != nil {
					return err
				}
				if err := guardProtection("host", "removing", prot); err != nil {
					return err
				}
				gone := map[string]string{} // name -> address
				var refs []string
				for _, n := range names {
					h := s.Hosts[n]
					gone[n] = trustAddr(h)
					refs = append(refs, h.PasswordRef, h.SudoRef, winrmCA(h))
					for _, v := range h.Env {
						refs = append(refs, v)
					}
					delete(s.Hosts, n)
				}
				kept = keptHostKeys(s, gone)
				unused = unusedSecrets(s, refs)
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "host.rm", names, "", true, nil)
			res := rmResult{Removed: names, HostKeysKept: kept, SecretsUnused: unused}
			if len(kept) > 0 {
				res.Note = "the pinned host keys of " + strings.Join(kept, ", ") + " stay in komando's known_hosts, so a server added again at the same address has to show the same key. " +
					"If it was rebuilt, add it again and replace the pin with `komando host trust NAME --reset` (a person confirms the new key)"
			}
			out.P.Print("host.rm", res, nil)
			return nil
		},
	}
}
