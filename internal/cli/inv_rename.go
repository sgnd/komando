package cli

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `host mv`, `conn mv` and `vpn mv` give an entry a new name. Everything
// about it stays (address, login, protected mark, groups, tags, labels),
// and every place in the inventory that names it follows: --via paths of
// servers, conns and tunnels, jobs and tunnels started on it. Pinned host
// keys belong to the address, not the name, so they stay valid. All of it
// changes in one write under the state lock, or not at all.

// mvResult is what the mv commands print.
type mvResult struct {
	Kind     string   `json:"kind"`   // host | conn | vpn | key | group
	From     string   `json:"from"`   // the old name
	To       string   `json:"to"`     // the new name
	Action   string   `json:"action"` // renamed | would_rename | unchanged
	Updated  []string `json:"updated"`
	Moved    []string `json:"moved,omitempty"` // key mv: the key files, "OLD -> NEW"
	Warnings []string `json:"warnings,omitempty"`
	// undo puts back what rename changed outside the state (vault
	// secrets) when the state cannot be saved after it
	undo func()
}

func (r mvResult) Text() string {
	if r.Action == "unchanged" {
		return fmt.Sprintf("%s %s already has that name\n", r.Kind, r.From)
	}
	verb := "renamed"
	if r.Action == "would_rename" {
		verb = "would rename"
	}
	s := fmt.Sprintf("%s %s %s to %s\n", verb, r.Kind, r.From, r.To)
	for _, u := range r.Updated {
		s += "  also updated: " + u + "\n"
	}
	for _, m := range r.Moved {
		s += "  moved: " + m + "\n"
	}
	for _, w := range r.Warnings {
		s += "  warning: " + w + "\n"
	}
	return s
}

// checkNewEntryName: to is a valid name for kind and no other entry uses
// it (case-only changes of the entry itself are fine).
func checkNewEntryName(s *store.State, kind, from, to string) error {
	check := func(n string) error { return validName(kind, n) }
	if kind == "host" {
		check = checkHostName
	}
	if err := check(to); err != nil {
		return err
	}
	if k, existing, ok := s.FindName(to); ok && !(k == kind && existing == from) {
		return nameTaken(k, existing)
	}
	return nil
}

// renameVia renames old in every --via path that names it (servers, conns,
// tunnels) and says which ones changed.
func renameVia(s *store.State, old, now string) []string {
	var updated []string
	for _, h := range s.SortedHosts() {
		if slices.Contains(viaChain(h.Via), old) {
			h.Via = renameStep(h.Via, old, now)
			updated = append(updated, "host "+h.Name+" --via")
		}
	}
	for _, c := range s.SortedConns() {
		if slices.Contains(viaChain(c.Via), old) {
			c.Via = renameStep(c.Via, old, now)
			updated = append(updated, "conn "+c.Name+" --via")
		}
	}
	for _, id := range mapKeys(s.Tunnels) {
		if t := s.Tunnels[id]; slices.Contains(viaChain(t.Via), old) {
			t.Via = renameStep(t.Via, old, now)
			updated = append(updated, "tunnel "+id+" --via")
		}
	}
	return updated
}

// renameHost renames a server in s. A protected one needs --yes (a person's
// yes for an AI agent), as for every change to a protected entry's identity.
func renameHost(s *store.State, from, to string) (mvResult, error) {
	h, err := findHost(s, from)
	if err != nil {
		return mvResult{}, err
	}
	res := mvResult{Kind: "host", From: h.Name, To: to, Updated: []string{}}
	if h.Name == to {
		res.Action = "unchanged"
		return res, nil
	}
	if err := checkNewEntryName(s, "host", h.Name, to); err != nil {
		return res, err
	}
	if h.Protected { // a second name for a protected server is marked protected when added
		if err := guardProtection("host", "renaming", []string{h.Name}); err != nil {
			return res, err
		}
	}
	old := h.Name
	delete(s.Hosts, old)
	h.Name, h.UpdatedAt = to, time.Now().UTC()
	s.Hosts[to] = h
	res.Updated = append(res.Updated, renameVia(s, old, to)...)
	for _, id := range mapKeys(s.Jobs) {
		if j := s.Jobs[id]; j.Host == old {
			j.Host = to
			res.Updated = append(res.Updated, "job "+id)
		}
	}
	for _, id := range mapKeys(s.Tunnels) {
		if t := s.Tunnels[id]; t.Host == old {
			t.Host = to
			res.Updated = append(res.Updated, "tunnel "+id)
		}
	}
	res.Action = mvVerb()
	return res, nil
}

// renameConn renames a conn in s; a protected one needs --yes.
func renameConn(s *store.State, from, to string) (mvResult, error) {
	c, err := findConn(s, from)
	if err != nil {
		return mvResult{}, err
	}
	res := mvResult{Kind: "conn", From: c.Name, To: to, Updated: []string{}}
	if c.Name == to {
		res.Action = "unchanged"
		return res, nil
	}
	if err := checkNewEntryName(s, "conn", c.Name, to); err != nil {
		return res, err
	}
	if c.Protected {
		if err := guardProtection("conn", "renaming", []string{c.Name}); err != nil {
			return res, err
		}
	}
	old := c.Name
	delete(s.Conns, old)
	c.Name, c.UpdatedAt = to, time.Now().UTC()
	s.Conns[to] = c
	for _, id := range mapKeys(s.Tunnels) {
		if t := s.Tunnels[id]; t.Conn == old {
			t.Conn = to
			res.Updated = append(res.Updated, "tunnel "+id)
		}
	}
	res.Action = mvVerb()
	return res, nil
}

// renameVpn renames a VPN in s. A connected VPN is refused: its background
// session runs under the old name. A Tailscale VPN's login state folder
// moves along (not under --dry-run).
func renameVpn(s *store.State, from, to string) (mvResult, error) {
	v, ok := s.Vpns[from]
	if !ok {
		return mvResult{}, notFoundSuggest("vpn", from, mapKeys(s.Vpns))
	}
	res := mvResult{Kind: "vpn", From: from, To: to, Updated: []string{}}
	if from == to {
		res.Action = "unchanged"
		return res, nil
	}
	if err := checkNewEntryName(s, "vpn", from, to); err != nil {
		return res, err
	}
	if _, up := s.Sessions[from]; up {
		return res, out.Errf(out.ExitConflict, "VPN_IN_USE", "disconnect it first with `komando vpn down "+from+"`, then rename it",
			"VPN %s is connected", from)
	}
	secrets, kept := vpnOwnSecrets(s, v, to)
	res.Warnings = append(res.Warnings, kept...)
	delete(s.Vpns, from)
	v.Name, v.UpdatedAt = to, time.Now().UTC()
	s.Vpns[to] = v
	res.Updated = append(res.Updated, renameVia(s, from, to)...)
	for _, n := range slices.Sorted(maps.Keys(secrets)) {
		renameSecretRefs(s, n, secrets[n])
		res.Updated = append(res.Updated, "secret "+n+", now "+secrets[n])
	}
	if len(secrets) > 0 && !g.dryRun {
		if err := vault.RenameMany(secrets); err != nil {
			return res, out.Errf(out.ExitError, "RENAME_FAILED", "nothing was renamed; check that the vault opens (`komando secret list`, KOMANDO_VAULT_PASS)",
				"the vault cannot rename the VPN's secrets: %v", err)
		}
		back := map[string]string{}
		for old, now := range secrets {
			back[now] = old
		}
		res.undo = func() { _ = vault.RenameMany(back) }
	}
	if v.Kind == "tailscale" {
		oldDir := netx.TailscaleDir(&store.Vpn{Name: from})
		if _, err := os.Stat(oldDir); err == nil {
			res.Updated = append(res.Updated, "login state folder")
			if !g.dryRun {
				if err := os.Rename(oldDir, netx.TailscaleDir(v)); err != nil && !errors.Is(err, os.ErrNotExist) {
					if res.undo != nil {
						res.undo()
						res.undo = nil
					}
					return res, out.Errf(out.ExitError, "RENAME_FAILED", "nothing was renamed; check the folder's permissions", "cannot move %s: %v", oldDir, err)
				}
			}
		}
	}
	res.Action = mvVerb()
	return res, nil
}

// vpnOwnSecrets are the vault secrets `vpn add` made for v under its name
// (NAME-key, -psk, -config, -pass) that only v uses, mapped to their names
// for the new name to, so that a renamed VPN leaves its old name free.
// kept says which of them keep their name, and why.
func vpnOwnSecrets(s *store.State, v *store.Vpn, to string) (map[string]string, []string) {
	pairs := map[string]string{}
	var kept []string
	have := secretNames()
	for _, suffix := range []string{"-key", "-psk", "-config", "-pass"} {
		n := v.Name + suffix
		ref := "secret:" + n
		if (v.KeyRef != ref && v.PSKRef != ref && v.ConfigRef != ref) || !slices.Contains(have, n) {
			continue
		}
		switch {
		case !slices.Equal(secretUsers(s, n), []string{"vpn " + v.Name}):
			kept = append(kept, "secret "+n+" keeps its name: something else uses it too")
		case slices.Contains(have, to+suffix):
			kept = append(kept, "secret "+n+" keeps its name: a secret "+to+suffix+" exists already")
		default:
			pairs[n] = to + suffix
		}
	}
	return pairs, kept
}

func mvVerb() string {
	if g.dryRun {
		return "would_rename"
	}
	return "renamed"
}

// mvCmd builds `KIND mv OLD NEW` around one of the rename functions.
func mvCmd(kind, example string, rename func(s *store.State, from, to string) (mvResult, error)) *cobra.Command {
	long := map[string]string{
		"host": `Gives a server a new name. Everything about it stays: address, login,
references, protected mark, groups, tags and labels. Servers, conns and
tunnels that reach other things through it (--via), and its jobs and
tunnels, follow the new name. Pinned host keys belong to the address, so
they stay. Renaming a protected server needs --yes.`,
		"conn": `Gives a conn a new name. Everything about it stays: URL, password
reference, protected mark, groups, tags, labels and options. Tunnels to it
follow the new name. Renaming a protected conn needs --yes.`,
		"vpn": `Gives a VPN a new name. Its settings stay, and every --via path that
starts with it follows the new name. The vault secrets ` + "`vpn add`" + ` made under
its name (NAME-key, NAME-config, ...) move to the new name when only this VPN
uses them, so the old name is free again. Disconnect it first
(` + "`komando vpn down NAME`" + `) if it is up.`,
	}[kind]
	return withID(&cobra.Command{
		Use:     "rename OLD NEW",
		Aliases: []string{"mv"}, // a permanent synonym; the ID stays kind.mv
		Short:   "Rename a " + formKindWord(kind) + " and every reference to it",
		Long:    long,
		Example: example,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res mvResult
			err := store.Update(func(s *store.State) error {
				var err error
				res, err = rename(s, args[0], args[1])
				return err
			})
			if err != nil {
				if res.undo != nil {
					res.undo()
				}
				return err
			}
			if res.Action == "renamed" {
				audit(nil, kind+".mv", []string{res.To}, "", true, map[string]any{"from": res.From, "to": res.To, "updated": len(res.Updated)})
			}
			out.P.Print(kind+".mv", res, nil)
			return nil
		},
	}, kind+".mv")
}

func hostMvCmd() *cobra.Command {
	return mvCmd("host", `  komando host rename web1 web-01
  komando host rename db1 prod-db1 --dry-run   # what would change
  komando host rename db1 prod-db1 --yes       # db1 is protected`, renameHost)
}

func connMvCmd() *cobra.Command {
	return mvCmd("conn", `  komando conn rename shop shop-prod
  komando conn rename prod-db main-db --yes    # prod-db is protected`, renameConn)
}

func vpnMvCmd() *cobra.Command {
	return mvCmd("vpn", `  komando vpn rename office office-jkt
  komando vpn rename office office-jkt --dry-run`, renameVpn)
}
