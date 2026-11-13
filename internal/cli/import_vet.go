package cli

import (
	"fmt"
	"os"

	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// hostVet is what an import may add, and why the rest is left out.
type hostVet struct {
	Add       []*store.Host
	Existing  []string     // same name already there (no --overwrite)
	Protected []string     // would replace a protected host (needs --yes)
	Invalid   []importSkip // names or settings komando refuses
	Notes     []string
}

// vetImportHosts checks imported hosts against s the way host add does:
// names, ports, users, --via paths. The file may come from someone else, so
// its hosts may not use secrets or files of this computer
// (dropForeignHostRefs), unless ownRefs says it is the user's own list (a
// CSV). A proxy command runs on this computer, so it goes through
// guardProxyCommand (an AI agent needs a person's yes). Without --yes (or
// --allow-dangerous) the host is only left out, so the rest still comes
// in; a person who says no in the window stops the whole import. Hosts
// that pass are put into s.
func vetImportHosts(s *store.State, hosts []*store.Host, overwrite, ownRefs bool) (hostVet, error) {
	var v hostVet
	var cand []*store.Host
	later := map[*store.Host][]string{} // what changed on a host; said only if it is added
	for _, h := range hosts {
		if h == nil || h.Name == "" || h.Address == "" {
			continue
		}
		if err := checkHostName(h.Name); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if kind, existing, ok := s.FindName(h.Name); ok {
			old, isHost := s.Hosts[h.Name]
			switch {
			case kind != "host" || existing != h.Name || !isHost:
				v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(nameTaken(kind, existing)).Message})
				continue
			case !overwrite:
				v.Existing = append(v.Existing, h.Name)
				continue
			case old.Protected && !yesOK():
				v.Protected = append(v.Protected, h.Name)
				continue
			}
		}
		h.Address = normAddr(h.Address)
		if h.Identity != "" {
			if _, err := os.Stat(expandHome(h.Identity)); err != nil {
				later[h] = append(later[h], h.Name+": its identity file "+h.Identity+" was not found; left out")
				h.Identity = ""
			}
		}
		if !ownRefs {
			later[h] = append(later[h], dropForeignHostRefs(h)...)
		}
		if h.Key != "" {
			if _, ok := s.Keys[h.Key]; !ok {
				// as with an identity file: the server comes in, its key
				// is said, and ssh-agent or a default key may log in
				// meanwhile (a key file is never in an export file)
				later[h] = append(later[h], fmt.Sprintf("%s: its key %s is not on this computer, so it was left out; copy the key file from the old computer and run `komando key add %s PATH` (a key komando made has no file: run `komando key gen %s` and put it on the server from the old computer), then `komando host edit %s --key %s`", h.Name, h.Key, h.Key, h.Key, h.Name, h.Key))
				h.Key = ""
			}
		}
		if err := checkEnvKeys(h.Env); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if err := checkHostRefs(h); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if r := proxyCommandSkip(h.ProxyCommand); r != "" {
			v.Invalid = append(v.Invalid, importSkip{h.Name, r})
			continue
		}
		if err := guardProxyCommand(h.ProxyCommand, h.Name); err != nil {
			return v, err
		}
		cand = append(cand, h)
	}
	prev := map[string]*store.Host{} // what --overwrite replaces, put back if the new one is refused
	for _, h := range cand {         // so they can be each other's --via
		if old, ok := s.Hosts[h.Name]; ok {
			prev[h.Name] = old
		}
		s.Hosts[h.Name] = h
	}
	for _, h := range cand {
		if err := checkHost(s, h); err != nil {
			if old, ok := prev[h.Name]; ok {
				s.Hosts[h.Name] = old
			} else {
				delete(s.Hosts, h.Name)
			}
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		v.Notes = append(v.Notes, later[h]...)
		if !h.Protected { // as host add does: a second name for a protected server
			if twin := protectedTwinHost(s, h); twin != "" {
				h.Protected = true
				v.Notes = append(v.Notes, sameTwinWarning("server", h.Name, twin))
			}
		}
		v.Add = append(v.Add, h)
	}
	return v, guardHostSends(v.Add, prev)
}

// proxyCommandSkip says why an import leaves out a host whose proxy
// command guardProxyCommand would stop and no flag asks to let through.
// With the flag, guardProxyCommand asks the person instead.
func proxyCommandSkip(cmd string) string {
	if cmd == "" {
		return ""
	}
	if hits := policy.Check(cmd, nil); len(hits) > 0 && !g.allowDangerous {
		return "its proxy command matches destructive rules (" + hits[0].Reason + "): import it again with --allow-dangerous once the user confirms it is intended"
	}
	if isAgent() && !g.yes {
		return "its proxy command runs on this computer, so an AI agent needs the user's yes: import it again with --yes after the user confirms"
	}
	return ""
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// vetImportRecipes picks the recipes an import adds: a name taken here
// (without --overwrite) or by a built-in recipe is skipped.
func vetImportRecipes(st *store.State, plan *importPlan, overwrite bool, res *importResult) []*store.Snippet {
	var recipes []*store.Snippet
	for _, r := range plan.Recipes {
		if _, ok := st.Snippets[r.Name]; (ok && !overwrite) || builtinRecipe(r.Name) != nil {
			res.Skipped = append(res.Skipped, importSkip{r.Name, "a recipe with this name exists"})
			continue
		}
		recipes = append(recipes, r)
		res.Recipes = append(res.Recipes, r.Name)
	}
	return recipes
}

// entryNames are the names of the servers, conns and VPNs in st.
func entryNames(st *store.State) map[string]bool {
	n := map[string]bool{}
	for k := range st.Hosts {
		n[k] = true
	}
	for k := range st.Conns {
		n[k] = true
	}
	for k := range st.Vpns {
		n[k] = true
	}
	return n
}
