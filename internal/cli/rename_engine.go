package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The rename engine behind `credential key rename` and `group rename`:
// renames done together, in one step. The inventory and the vault are
// each written once, after every check passed, or not at all. Every
// reference follows (--via paths, password and other refs, credential:NAME in a
// conn URL, the key a server uses, group membership), as `host mv`, `secret
// mv` and the others do for one entry.

// renameKinds are the kinds a rename covers, in the order it reports them.
var renameKinds = []string{"host", "conn", "vpn", "secret", "key", "group"}

// renameSet is the renames done together: kind -> old name -> new name.
type renameSet map[string]map[string]string

func (rs renameSet) size() int {
	n := 0
	for _, m := range rs {
		n += len(m)
	}
	return n
}

// renamePair is one rename, or one file that moves.
type renamePair struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Protected bool   `json:"protected,omitempty"`
}

// renameRef is one reference the rename changes.
type renameRef struct {
	Entry string `json:"entry"` // kind and name after the rename: "host web-01"
	Field string `json:"field"` // via, password_ref, url, groups, ...
	From  string `json:"from"`
	To    string `json:"to"`
}

func (r renameRef) String() string { return r.Entry + " " + r.Field }

// renameOpts are the choices of one rename.
type renameOpts struct {
	// guard asks for a person's yes before protected servers and conns
	// change (prot: "host NAME", "conn NAME"); nil when no yes is needed
	guard func(prot []string) error
}

// renameTx does one rename under the state lock: plan picks the renames
// from the locked state, applyRenames changes the state, then the vault
// secrets and the VPN folders move, and the state is saved
// last. When anything fails (a check, the vault, a file, the save), what
// already moved is put back and the state is not saved, so nothing
// changes. Under --dry-run only the plan runs.
func renameTx(cl *call, plan func(s *store.State) (renameSet, renameOpts, error)) (renameResult, error) {
	var res renameResult
	var moves []renamePair
	var secrets map[string]string
	moved := 0
	// the questions first, outside the store's lock: plan and applyRenames
	// change only the copy; the vault and files move only inside the step
	if err := askFirst(cl, func(s *store.State) error {
		set, opts, err := plan(s)
		if err != nil {
			return err
		}
		_, _, err = applyRenames(cl, s, set, opts)
		return err
	}); err != nil {
		return renameResult{}, err
	}
	err := storeUpdate(cl, func(s *store.State) error {
		set, opts, err := plan(s)
		if err != nil {
			return err
		}
		if res, moves, err = applyRenames(cl, s, set, opts); err != nil || cl.dryRun() || set.size() == 0 {
			return err
		}
		if sec := set["secret"]; len(sec) > 0 {
			if err := vault.RenameMany(cl.storeWrite(), sec); err != nil {
				return out.Errf(out.ExitError, "RENAME_FAILED", "check that the vault opens (`komando credential list`, KOMANDO_VAULT_PASS)",
					"the vault cannot rename the secrets: %v; nothing was renamed", err)
			}
			secrets = sec
		}
		for _, m := range moves {
			if err := os.Rename(m.From, m.To); err != nil {
				return out.Errf(out.ExitError, "RENAME_FAILED", "check the permissions of "+filepath.Dir(m.From),
					"cannot move %s: %v; nothing was renamed", m.From, errText(err))
			}
			moved++
		}
		return nil
	})
	if err != nil {
		for i := moved - 1; i >= 0; i-- {
			_ = os.Rename(moves[i].To, moves[i].From)
		}
		if secrets != nil {
			back := make(map[string]string, len(secrets))
			for from, to := range secrets {
				back[to] = from
			}
			_ = vault.RenameMany(cl.storeWrite(), back)
		}
		return res, err
	}
	return res, nil
}

// applyRenames checks set against s and, when every check passes, renames
// in s: the entries, then every reference to them. It returns the files
// that must move (key files, a Tailscale VPN's state folder); renameTx
// moves them.
func applyRenames(cl *call, s *store.State, set renameSet, opts renameOpts) (renameResult, []renamePair, error) {
	res := renameResult{Action: mvVerb(cl), Renamed: map[string][]renamePair{}, Protected: []string{}, Updated: []renameRef{}, Moved: []renamePair{}}
	if set.size() == 0 {
		res.Action = "unchanged"
		return res, nil, nil
	}
	if err := checkRenameSet(cl, s, set); err != nil {
		return res, nil, err
	}
	res.Protected = renameProtected(s, set)
	if len(res.Protected) > 0 && opts.guard != nil {
		if err := opts.guard(res.Protected); err != nil {
			return res, nil, err
		}
	}
	rw := newRefRewriter(set, opts, &res)
	moves := rw.renameEntries(s)
	res.Count = set.size()
	res.Moved = append(res.Moved, moves...)
	rw.rewrite(s)
	return res, moves, nil
}

// renameProtected is the protected servers and conns a rename changes:
// renamed, or a group of theirs renamed. Pointing a reference at a new name
// of the same secret, key or VPN sends the same thing to the same place,
// so it needs no yes (as with `credential password rename` and `vpn mv`).
func renameProtected(s *store.State, set renameSet) []string {
	prot := []string{}
	for _, h := range s.SortedHosts() {
		if _, ok := set["host"][h.Name]; h.Protected && (ok || inRenamedGroup(set["group"], h.Groups)) {
			prot = append(prot, "host "+h.Name)
		}
	}
	for _, c := range s.SortedConns() {
		if _, ok := set["conn"][c.Name]; c.Protected && (ok || inRenamedGroup(set["group"], c.Groups)) {
			prot = append(prot, "conn "+c.Name)
		}
	}
	return prot
}

func inRenamedGroup(gm map[string]string, gs []string) bool {
	return slices.ContainsFunc(gs, func(x string) bool { _, ok := gm[x]; return ok })
}

// refRewriter renames the entries of a renameSet in the state, then points
// every reference at the new names, and records each change in res.
type refRewriter struct {
	rs      renameSet
	opts    renameOpts
	steps   map[string]string // --via steps name servers and VPNs
	res     *renameResult
	now     time.Time
	touched bool // the entry being rewritten changed
}

func newRefRewriter(rs renameSet, opts renameOpts, res *renameResult) *refRewriter {
	w := &refRewriter{rs: rs, opts: opts, steps: map[string]string{}, res: res, now: time.Now().UTC()}
	maps.Copy(w.steps, rs["host"])
	maps.Copy(w.steps, rs["vpn"])
	return w
}

// renameEntries gives every entry in the set its new name and returns the
// files that move with it.
func (w *refRewriter) renameEntries(s *store.State) []renamePair {
	var moves []renamePair
	for _, k := range renameKinds {
		for _, from := range slices.Sorted(maps.Keys(w.rs[k])) {
			p := renamePair{From: from, To: w.rs[k][from]}
			switch k {
			case "host":
				h := s.Hosts[from]
				delete(s.Hosts, from)
				h.Name, h.UpdatedAt, p.Protected = p.To, w.now, h.Protected
				s.Hosts[p.To] = h
			case "conn":
				c := s.Conns[from]
				delete(s.Conns, from)
				c.Name, c.UpdatedAt, p.Protected = p.To, w.now, c.Protected
				s.Conns[p.To] = c
			case "vpn":
				v := s.Vpns[from]
				delete(s.Vpns, from)
				v.Name, v.UpdatedAt = p.To, w.now
				s.Vpns[p.To] = v
				if v.Kind == "tailscale" {
					oldDir := netx.TailscaleDir(&store.Vpn{Name: from})
					if _, err := os.Stat(oldDir); err == nil {
						moves = append(moves, renamePair{From: oldDir, To: netx.TailscaleDir(v)})
					}
				}
			case "key":
				w.renameKey(s, from, p.To)
			}
			w.res.Renamed[k] = append(w.res.Renamed[k], p)
		}
	}
	return moves
}

// renameKey renames a key. A key komando made lives in the store, so no
// file moves; a key added from elsewhere (key add) keeps its file where it
// is.
func (w *refRewriter) renameKey(s *store.State, from, to string) {
	key := s.Keys[from]
	delete(s.Keys, from)
	key.Name = to
	s.Keys[to] = key
}

// change sets *p to v and records it.
func (w *refRewriter) change(entry, field string, p *string, v string) {
	if *p != v {
		w.res.Updated = append(w.res.Updated, renameRef{entry, field, *p, v})
		*p, w.touched = v, true
	}
}

// ref is a reference with a renamed secret's new name.
func (w *refRewriter) ref(r string) string {
	if n, ok := strings.CutPrefix(r, "credential:"); ok {
		if to, ok := w.rs["secret"][n]; ok {
			return "credential:" + to
		}
	}
	return r
}

// via is a --via path with every renamed step's new name, wherever it is.
func (w *refRewriter) via(v string) string {
	chain := inventory.ViaChain(v)
	changed := false
	for i, st := range chain {
		if to, ok := w.steps[st]; ok {
			chain[i], changed = to, true
		}
	}
	if !changed {
		return v
	}
	return strings.Join(chain, ",")
}

// url changes only ?option=credential:NAME in a conn URL: names of buckets,
// users and databases in it are the resource's own, not komando's.
func (w *refRewriter) url(u string) string {
	return inventory.MapURLSecretRefs(u, func(_, name string) string {
		if to, ok := w.rs["secret"][name]; ok {
			return to
		}
		return name
	})
}

func (w *refRewriter) groups(entry string, p *[]string) {
	gm := w.rs["group"]
	if !inRenamedGroup(gm, *p) {
		return
	}
	ng := make([]string, len(*p))
	for i, x := range *p {
		ng[i] = x
		if to, ok := gm[x]; ok {
			ng[i] = to
		}
	}
	if ng = dedupe(ng); !slices.Equal(ng, *p) {
		w.res.Updated = append(w.res.Updated, renameRef{entry, "groups", strings.Join(*p, ","), strings.Join(ng, ",")})
		*p, w.touched = ng, true
	}
}

// rewrite points every reference in s at the new names.
func (w *refRewriter) rewrite(s *store.State) {
	for _, h := range s.SortedHosts() {
		e := "host " + h.Name
		w.touched = false
		w.change(e, "via", &h.Via, w.via(h.Via))
		if to, ok := w.rs["key"][h.Key]; ok {
			w.change(e, "key", &h.Key, to)
		}
		w.change(e, "password_ref", &h.PasswordRef, w.ref(h.PasswordRef))
		w.change(e, "sudo_ref", &h.SudoRef, w.ref(h.SudoRef))
		for _, name := range slices.Sorted(maps.Keys(h.Env)) {
			v := h.Env[name]
			w.change(e, "env "+name, &v, w.ref(v))
			h.Env[name] = v
		}
		w.groups(e, &h.Groups)
		if w.touched {
			h.UpdatedAt = w.now
		}
	}
	for _, c := range s.SortedConns() {
		e := "conn " + c.Name
		w.touched = false
		w.change(e, "via", &c.Via, w.via(c.Via))
		w.change(e, "password_ref", &c.PasswordRef, w.ref(c.PasswordRef))
		w.change(e, "url", &c.URL, w.url(c.URL))
		w.groups(e, &c.Groups)
		if w.touched {
			c.UpdatedAt = w.now
		}
	}
	for _, v := range s.SortedVpns() {
		e := "vpn " + v.Name
		w.touched = false
		w.change(e, "key_ref", &v.KeyRef, w.ref(v.KeyRef))
		w.change(e, "psk_ref", &v.PSKRef, w.ref(v.PSKRef))
		w.change(e, "config_ref", &v.ConfigRef, w.ref(v.ConfigRef))
		w.groups(e, &v.Groups)
		if w.touched {
			v.UpdatedAt = w.now
		}
	}
	w.rewriteRest(s)
}

// rewriteRest: key passphrases, exec sessions and tunnels.
func (w *refRewriter) rewriteRest(s *store.State) {
	for _, name := range slices.Sorted(maps.Keys(s.Keys)) {
		k := s.Keys[name]
		w.change("key "+name, "passphrase_ref", &k.PassphraseRef, w.ref(k.PassphraseRef))
	}
	for _, id := range slices.Sorted(maps.Keys(s.ExecSessions)) {
		if e := s.ExecSessions[id]; w.rs["host"][e.Host] != "" {
			w.change("exec session "+id, "host", &e.Host, w.rs["host"][e.Host])
		}
	}
	for _, id := range slices.Sorted(maps.Keys(s.Tunnels)) {
		t := s.Tunnels[id]
		if to := w.rs["host"][t.Host]; to != "" {
			w.change("tunnel "+id, "host", &t.Host, to)
		}
		if to := w.rs["conn"][t.Conn]; to != "" {
			w.change("tunnel "+id, "conn", &t.Conn, to)
		}
		w.change("tunnel "+id, "via", &t.Via, w.via(t.Via))
	}
}

// renameChecker collects what stops a rename.
type renameChecker struct {
	cl      *call // the call it works for
	s       *store.State
	secrets []string          // the vault's names, when secrets are renamed
	groups  []string          // every group as written
	shared  map[string]string // lower-case new name -> "kind old": servers, conns and VPNs share one name space
	clashes []string
}

// checkRenameSet refuses a rename that cannot be done in full: an old name
// that is gone, a new name that is not valid or reserved, a VPN that is
// connected, and every clash. A clash is a new name that exists already
// (servers, conns and VPNs share one name space, ignoring case; so do
// groups), a key file in the way, or two old names with one new name. A
// new name that exists is refused even when it is renamed too: no swaps or
// chains, so a reference komando does not know of (a {{credential:NAME}} in a
// file on a server) never gets another entry's value.
func checkRenameSet(cl *call, s *store.State, set renameSet) error {
	c := &renameChecker{cl: cl, s: s, groups: slices.Sorted(maps.Keys(allGroups(s).Groups)), shared: map[string]string{}}
	if len(set["secret"]) > 0 {
		c.secrets = secretNames()
	}
	for _, k := range renameKinds {
		news := map[string]string{} // new name (lower case for groups) -> old
		for _, from := range slices.Sorted(maps.Keys(set[k])) {
			to := set[k][from]
			if err := c.check(k, from, to); err != nil {
				return err
			}
			if k == "host" || k == "conn" || k == "vpn" {
				continue // checked in the shared name space
			}
			key := to
			if k == "group" {
				key = strings.ToLower(to)
			}
			// two spellings of one group (Web, web) may become one name
			if other, ok := news[key]; ok && !(k == "group" && strings.EqualFold(other, from)) {
				c.clashes = append(c.clashes, fmt.Sprintf("%s %s and %s would both be named %s", k, other, from, to))
			}
			news[key] = from
		}
	}
	if len(c.clashes) > 0 {
		return out.Errf(out.ExitConflict, "NAME_TAKEN", "pick other names, or rename or remove what is in the way first",
			"the rename clashes: %s; nothing was renamed", strings.Join(c.clashes, "; "))
	}
	for _, from := range slices.Sorted(maps.Keys(set["vpn"])) {
		if _, up := s.Sessions[from]; up {
			return out.Errf(out.ExitConflict, "VPN_IN_USE", "disconnect it first with `komando vpn "+s.Vpns[from].Kind+" stop "+from+"`, then rename",
				"VPN %s is connected; nothing was renamed", from)
		}
		if s.Vpns[from].Kind != "tailscale" {
			continue
		}
		if _, err := os.Stat(netx.TailscaleDir(&store.Vpn{Name: set["vpn"][from]})); err == nil {
			return out.Errf(out.ExitConflict, "NAME_TAKEN", "move that folder away first",
				"the login state folder of a VPN named %s is in the way; nothing was renamed", set["vpn"][from])
		}
	}
	return nil
}

// check is one rename of kind k: an error stops at once, a clash is
// collected so the message lists them all.
func (c *renameChecker) check(k, from, to string) error {
	valid := inventory.ValidName
	if k == "group" {
		valid = inventory.ValidLabelName
	}
	if err := valid(k, to); err != nil {
		return err
	}
	s := c.s
	switch k {
	case "host", "conn", "vpn":
		if !map[string]bool{"host": s.Hosts[from] != nil, "conn": s.Conns[from] != nil, "vpn": s.Vpns[from] != nil}[k] {
			return notFoundSuggest(c.cl, k, from, nil)
		}
		if kind, existing, ok := s.FindName(to); ok && !(kind == k && existing == from) {
			c.clashes = append(c.clashes, fmt.Sprintf("%s %s would take the name of %s %s", k, from, kind, existing))
		}
		if other, ok := c.shared[strings.ToLower(to)]; ok {
			c.clashes = append(c.clashes, fmt.Sprintf("%s and %s %s would both be named %s", other, k, from, to))
		}
		c.shared[strings.ToLower(to)] = k + " " + from
	case "secret":
		for _, n := range []string{from, to} {
			if err := reservedSecret(n); err != nil {
				return err
			}
		}
		if !slices.Contains(c.secrets, from) {
			return notFoundSuggest(c.cl, "secret", from, c.secrets)
		}
		if slices.Contains(c.secrets, to) {
			c.clashes = append(c.clashes, fmt.Sprintf("secret %s would take the name of secret %s", from, to))
		}
	case "key":
		if s.Keys[from] == nil {
			return keyNotFound(c.cl, s, from)
		}
		if s.Keys[to] != nil {
			c.clashes = append(c.clashes, fmt.Sprintf("key %s would take the name of key %s", from, to))
		}
	case "group":
		if !slices.Contains(c.groups, from) {
			return groupNotFound(c.cl, s, from)
		}
		if !strings.EqualFold(from, to) && slices.ContainsFunc(c.groups, func(x string) bool { return strings.EqualFold(x, to) }) {
			c.clashes = append(c.clashes, fmt.Sprintf("group %s would take the name of group %s", from, to))
		}
	}
	return nil
}
