package cli

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
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
// guardProxyCommand (an AI agent needs a person's yes), and so does
// forward_agent on a host that did not lend the ssh-agent before (as host
// edit --forward-agent). Without --yes (or
// --allow-dangerous) the host is only left out, so the rest still comes
// in; a person who says no in the window stops the whole import. Hosts
// that pass are put into s.
func vetImportHosts(cl *call, s *store.State, hosts []*store.Host, overwrite, ownRefs bool) (hostVet, error) {
	var v hostVet
	var cand []*store.Host
	var lend []string                   // hosts the file would lend the ssh-agent to
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
				v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(inventory.NameTaken(kind, existing)).Message})
				continue
			case !overwrite:
				v.Existing = append(v.Existing, h.Name)
				continue
			case old.Protected && !cl.yesOK():
				v.Protected = append(v.Protected, h.Name)
				continue
			}
		}
		h.Address = inventory.NormAddr(h.Address)
		if h.Identity != "" {
			if _, err := os.Stat(inventory.ExpandHome(h.Identity)); err != nil {
				later[h] = append(later[h], h.Name+": its identity file "+h.Identity+" was not found; left out")
				h.Identity = ""
			}
		}
		if !ownRefs {
			later[h] = append(later[h], dropForeignHostRefs(cl, h)...)
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
		if err := checkEnv(h.Env); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if err := checkHostRefs(h); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if skip, err := vetProxyCommand(cl, h); err != nil {
			return v, err
		} else if skip != "" {
			v.Invalid = append(v.Invalid, importSkip{h.Name, skip})
			continue
		}
		if old, ok := s.Hosts[h.Name]; h.ForwardAgent && (!ok || !old.ForwardAgent) {
			lend = append(lend, h.Name)
		}
		cand = append(cand, h)
	}
	// as host edit --forward-agent: a person decides
	if len(lend) > 0 {
		if err := guardSafety(cl, forwardAgentWhat(lend)); err != nil {
			return v, err
		}
	}
	prev := map[string]*store.Host{} // what --overwrite replaces, put back if the new one is refused
	for _, h := range cand {         // so they can be each other's --via
		if old, ok := s.Hosts[h.Name]; ok {
			prev[h.Name] = old
		}
		s.Hosts[h.Name] = h
	}
	for _, h := range cand {
		if err := checkHost(cl, s, h); err != nil {
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
	return v, guardHostSends(cl, s, v.Add, prev)
}

// vetProxyCommand decides an imported host's proxy command: skip says why
// the import leaves the host out (a dry run records that stop); err stops
// the whole import (the person said no in the window).
func vetProxyCommand(cl *call, h *store.Host) (skip string, err error) {
	if e := proxyCommandSkip(cl, h.ProxyCommand); e != nil {
		_ = cl.policyStop(e) // a dry run records the stop the real import leaves it out for
		return e.Message, nil
	}
	return "", guardProxyCommand(cl, h.ProxyCommand, h.Name)
}

// proxyCommandSkip is the stop for which an import leaves out a host whose
// proxy command guardProxyCommand would stop and no flag asks to let
// through, or nil; its message is the reason the import gives. With the
// flag, guardProxyCommand asks the person instead.
func proxyCommandSkip(cl *call, cmd string) *out.Error {
	if cmd == "" {
		return nil
	}
	if hits := policy.Check(cmd, nil); len(hits) > 0 && !cl.allowDangerous() {
		return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "import it again with --allow-dangerous once the user confirms it is intended",
			"its proxy command matches destructive rules (%s): import it again with --allow-dangerous once the user confirms it is intended", hits[0].Reason)
	}
	if cl.isAgent() && !cl.yes() {
		return out.Errf(out.ExitPolicy, "SAFETY_SETTING", "import it again with --yes after the user confirms",
			"its proxy command runs on this computer, so an AI agent needs the user's yes: import it again with --yes after the user confirms")
	}
	return nil
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

// guardImportVpns asks for what the imported VPNs weaken, as vpn add and
// vpn edit do: the weaker logins they turn on (importVpnOptIns), a CA
// they no longer check the server against and secrets they send
// (guardVpnSends), and, for a VPN they replace, protection or --mfa
// turned off (guardVpnEdit). A file cannot do what a person did not allow.
func guardImportVpns(cl *call, st *store.State, vpns []*store.Vpn) error {
	if err := importVpnPlaces(cl, st, vpns); err != nil { // an agent: no yes lifts it
		return err
	}
	olds := map[string]*store.Vpn{}
	var replaced []*store.Vpn
	for _, v := range vpns {
		if err := importVpnOptIns(cl, st, v); err != nil {
			return err
		}
		old := st.Vpns[v.Name]
		if err := guardVpnSends(cl, st, old, v, "", true); err != nil {
			return err
		}
		if old != nil {
			olds[v.Name] = old
			replaced = append(replaced, v)
		}
	}
	return guardVpnEdit(cl, olds, replaced)
}

// guardImportSecrets is secret set's guard for the secrets an import
// writes (a conn's password it carries is stored as NAME-pass, whoever
// else uses that name): one on the way to a login-ask server or conn
// stops an AI agent, whether it is there already or only named
// (loginPlaceStop), and replacing one a protected entry uses needs a
// person's yes.
func guardImportSecrets(cl *call, st *store.State, names []string, plan *importPlan) error {
	for _, name := range names {
		if err := loginPlaceStop(cl, secretPlaceChanges(st, name)); err != nil {
			return err
		}
		if _, err := vault.Get(name); errors.Is(err, vault.ErrNotFound) {
			continue // a new secret replaces nothing
		} else if err != nil {
			return err
		}
		if prot := inventory.ProtectedUsers(st, inventory.SecretUsers(st, name)); len(prot) > 0 && !cl.yesOK() && !confirmProtected(cl, prot) {
			if err := cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
				"secret "+name+" is used by protected "+strings.Join(prot, ", ")+"; replacing it changes how komando logs in there")); err != nil {
				return err
			}
		}
	}
	// and secret set's check of whom komando trusts
	values := map[string]string{}
	for _, n := range names {
		values[n] = cmp.Or(plan.Secrets[n], plan.SealedSecrets[n])
	}
	return guardImportedTrust(cl, st, values)
}

// importVpnOptIns asks for the weaker logins an imported VPN turns on, as
// vpn edit does (vpnOptIns): a file cannot allow old ciphers or PAP that
// a person did not. A setting the VPN's kind does not use is dropped.
func importVpnOptIns(cl *call, st *store.State, v *store.Vpn) error {
	cur := &store.Vpn{Name: v.Name, Kind: v.Kind}
	if old, ok := st.Vpns[v.Name]; ok && old.Kind == v.Kind {
		cur.LegacyCrypto, cur.AllowPAP = old.LegacyCrypto, old.AllowPAP
	}
	v.LegacyCrypto = v.LegacyCrypto && vpnTakes(v.Kind, "legacy-crypto")
	v.AllowPAP = v.AllowPAP && vpnTakes(v.Kind, "allow-pap")
	set := map[string]bool{"legacy-crypto": v.LegacyCrypto, "allow-pap": v.AllowPAP}
	return vpnOptIns(cl, cur, func(f string) bool { return set[f] }, v.LegacyCrypto, v.AllowPAP)
}

// importHostSecrets records the passwords an import brings for its
// servers (FileZilla), under the name each server's --password-ref points
// at, so they go to the vault. A name already in the vault never gets
// here: vetImportHosts drops that reference (dropForeignHostRefs).
func importHostSecrets(hosts []*store.Host, plan *importPlan, res *importResult) []*store.Host {
	for _, h := range hosts {
		if name, ok := strings.CutPrefix(h.PasswordRef, "credential:"); ok && plan.Secrets[name] != "" {
			res.Secrets = append(res.Secrets, name)
		}
	}
	return hosts
}
