package cli

import (
	"fmt"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The rename engine behind `komando rename --starts-with`, `key mv` and `group
// mv`: many renames at once, in one step. The inventory and the vault are
// each written once, after every check passed, or not at all. Every
// reference follows (--via paths, password and other refs, secret:NAME in a
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

// renameKept is an old name left as it is in a note or a label value, and
// why. To is what --in-labels would make of a label value.
type renameKept struct {
	Entry  string `json:"entry"` // kind and name after the rename: "host web-01"
	Field  string `json:"field"` // notes, or "label KEY"
	Name   string `json:"name"`  // the old name, pattern or label value as written
	To     string `json:"to,omitempty"`
	Reason string `json:"reason"`
}

// renameOpts are the choices of one rename.
type renameOpts struct {
	notes  bool // replace old names in notes too (see nameText)
	labels bool // and in label values
	// prefix is OLD and NEW of `rename --starts-with`, for the notes and labels
	// that name old entries; nil for key mv and group mv
	prefix *renamePair
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
	err := store.Update(func(s *store.State) error {
		set, opts, err := plan(s)
		if err != nil {
			return err
		}
		if res, moves, err = applyRenames(cl, s, set, opts); err != nil || cl.flags.dryRun || set.size() == 0 {
			return err
		}
		if sec := set["secret"]; len(sec) > 0 {
			if err := vault.RenameMany(sec); err != nil {
				return out.Errf(out.ExitError, "RENAME_FAILED", "check that the vault opens (`komando secret list`, KOMANDO_VAULT_PASS)",
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
			_ = vault.RenameMany(back)
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
	rw := newRefRewriter(s, set, opts, &res)
	moves := rw.renameEntries(s)
	res.Count = set.size()
	res.Moved = append(res.Moved, moves...)
	rw.rewrite(s)
	if rw.notesLeft > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the notes of %d %s name old entries and stay as they are; --in-notes replaces them (see each with --in-notes --dry-run)",
			rw.notesLeft, renameNoun(rw.notesLeft, "entry")))
	}
	return res, moves, nil
}

// renameProtected is the protected servers and conns a rename changes:
// renamed, or a group of theirs renamed. Pointing a reference at a new name
// of the same secret, key or VPN sends the same thing to the same place,
// so it needs no yes (as with `secret mv` and `vpn mv`).
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
	rs        renameSet
	opts      renameOpts
	steps     map[string]string // --via steps name servers and VPNs
	text      *nameText         // old names in notes and labels; nil for key mv and group mv
	notesLeft int               // entries whose notes --in-notes would change, when it is not given
	res       *renameResult
	now       time.Time
	touched   bool // the entry being rewritten changed
}

// newRefRewriter is made before the entries get their new names: the
// notes and labels compare against the names as they were.
func newRefRewriter(s *store.State, rs renameSet, opts renameOpts, res *renameResult) *refRewriter {
	w := &refRewriter{rs: rs, opts: opts, steps: map[string]string{}, res: res, now: time.Now().UTC()}
	maps.Copy(w.steps, rs["host"])
	maps.Copy(w.steps, rs["vpn"])
	if opts.prefix != nil || opts.notes || opts.labels {
		w.text = newNameText(s, rs, opts.prefix)
	}
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
	if n, ok := strings.CutPrefix(r, "secret:"); ok {
		if to, ok := w.rs["secret"][n]; ok {
			return "secret:" + to
		}
	}
	return r
}

// via is a --via path with every renamed step's new name, wherever it is.
func (w *refRewriter) via(v string) string {
	chain := viaChain(v)
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

// url changes only ?option=secret:NAME in a conn URL: names of buckets,
// users and databases in it are the resource's own, not komando's.
func (w *refRewriter) url(u string) string {
	return mapURLSecretRefs(u, func(_, name string) string {
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

// notes replaces the old names in a note with --in-notes. Without it, the
// note stays and is only counted for one warning.
func (w *refRewriter) notes(entry string, p *string) {
	if w.text == nil || *p == "" {
		return
	}
	nt, kept := w.text.replace(*p)
	if !w.opts.notes {
		if nt != *p {
			w.notesLeft++
		}
		return
	}
	w.keep(entry, "notes", kept)
	w.change(entry, "notes", p, nt)
}

// labels replaces the old names in label values with --in-labels, as notes
// does; label names stay. Labels are free text, so without --in-labels each
// value that would change is listed as kept, with what it would become.
func (w *refRewriter) labels(entry string, m map[string]string) {
	if w.text == nil {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		v, f := m[k], "label "+k
		nv, kept := w.text.replace(v)
		w.keep(entry, f, kept)
		switch {
		case nv == v:
		case w.opts.labels:
			w.change(entry, f, &v, nv)
			m[k] = v
		default:
			w.res.Kept = append(w.res.Kept, renameKept{Entry: entry, Field: f, Name: v, To: nv, Reason: "labels change only with --in-labels"})
		}
	}
}

// keep records the old names a note or label value keeps, once each.
func (w *refRewriter) keep(entry, field string, kept []keptWord) {
	seen := map[string]bool{}
	for _, k := range kept {
		if !seen[k.name] {
			seen[k.name] = true
			w.res.Kept = append(w.res.Kept, renameKept{Entry: entry, Field: field, Name: k.name, Reason: k.reason})
		}
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
		w.labels(e, h.Labels)
		w.notes(e, &h.Notes)
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
		w.labels(e, c.Labels)
		w.notes(e, &c.Notes)
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
		w.labels(e, v.Labels)
		w.notes(e, &v.Notes)
		if w.touched {
			v.UpdatedAt = w.now
		}
	}
	w.rewriteRest(s)
}

// rewriteRest: key passphrases, jobs and tunnels.
func (w *refRewriter) rewriteRest(s *store.State) {
	for _, name := range mapKeys(s.Keys) {
		k := s.Keys[name]
		w.change("key "+name, "passphrase_ref", &k.PassphraseRef, w.ref(k.PassphraseRef))
	}
	for _, id := range mapKeys(s.Jobs) {
		if j := s.Jobs[id]; w.rs["host"][j.Host] != "" {
			w.change("job "+id, "host", &j.Host, w.rs["host"][j.Host])
		}
	}
	for _, id := range mapKeys(s.Tunnels) {
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
// chains, so a reference komando does not know of (a {{secret:NAME}} in a
// file on a server) never gets another entry's value.
func checkRenameSet(cl *call, s *store.State, set renameSet) error {
	c := &renameChecker{cl: cl, s: s, groups: mapKeys(allGroups(s).Groups), shared: map[string]string{}}
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
	for _, from := range mapKeys(set["vpn"]) {
		if _, up := s.Sessions[from]; up {
			return out.Errf(out.ExitConflict, "VPN_IN_USE", "disconnect it first with `komando vpn down "+from+"`, then rename",
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
	valid := validName
	if k == "group" {
		valid = validLabelName
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

// nameText replaces old names in free text: notes (--in-notes) and label
// values (--in-labels). Free text names more than komando's entries, so only
// what clearly means an entry follows:
//
//   - the names of servers, conns, VPNs and secrets, as whole words (not
//     part of a longer name: letters, digits, . _ -);
//   - a group written @NAME, as in a target;
//   - a pattern such as shop-db-* that starts with OLD, when every server,
//     conn and VPN it matches is renamed and the new pattern matches no
//     other (a target written in a note keeps meaning the same entries).
//
// Some old names stay, and the result lists each with the reason: OLD
// without its - (shop for --starts-with shop-), which is usually a plain word
// such as a database or a role; group names written without @; key names,
// which often name an environment, a bucket or an account too; and a name
// that is also the user, host, bucket or database in a conn URL, which
// may mean that resource rather than komando's entry.
type nameText struct {
	follow   map[string]string // servers, conns, VPNs, secrets: old -> new
	groups   map[string]string // groups, as @NAME
	left     map[string]string // old names that stay as plain words -> why
	inURL    map[string]string // words in conn URLs -> the conn (new name)
	old, new string            // the prefix, for patterns; "" for none
	grows    bool              // new starts with old
	before   []string          // servers, conns and VPNs before the rename
	renamed  map[string]string // servers, conns and VPNs: old -> new
}

// keptWord is an old name a text keeps, and why.
type keptWord struct{ name, reason string }

func newNameText(s *store.State, rs renameSet, prefix *renamePair) *nameText {
	t := &nameText{follow: map[string]string{}, groups: rs["group"], left: map[string]string{}, inURL: map[string]string{}, renamed: map[string]string{}}
	for _, k := range []string{"host", "conn", "vpn"} {
		maps.Copy(t.renamed, rs[k])
	}
	maps.Copy(t.follow, t.renamed)
	maps.Copy(t.follow, rs["secret"])
	for n := range rs["key"] {
		t.left[n] = "a key's name, which often names a bucket, an account or an environment too"
	}
	for n := range rs["group"] {
		why := "a group's name, often a plain word too"
		if k, ok := t.left[n]; ok {
			why = k
		}
		t.left[n] = why + "; @" + n + " follows the group"
	}
	if prefix != nil {
		t.old, t.new = prefix.From, prefix.To
		t.grows = len(t.new) > len(t.old) && strings.HasPrefix(t.new, t.old)
		if bare, ok := strings.CutSuffix(t.old, "-"); ok && bare != "" {
			for _, k := range renameKinds {
				if _, ok := rs[k][bare]; ok {
					why := "OLD without its -, usually a plain word (a database, a role)"
					if _, g := rs["group"][bare]; g {
						why += "; @" + bare + " follows the group"
					}
					delete(t.follow, bare)
					t.left[bare] = why
					break
				}
			}
		}
	}
	for n := range t.follow {
		delete(t.left, n) // a key or group that shares a server's name follows with it
	}
	for _, h := range s.SortedHosts() {
		t.before = append(t.before, h.Name)
	}
	for _, c := range s.SortedConns() {
		t.before = append(t.before, c.Name)
		name := c.Name
		if to, ok := t.renamed[name]; ok {
			name = to
		}
		for _, w := range urlWords(c.URL) {
			if _, ok := t.inURL[w]; !ok {
				t.inURL[w] = name
			}
		}
	}
	for _, v := range s.SortedVpns() {
		t.before = append(t.before, v.Name)
	}
	return t
}

// urlWords are the names in a conn URL that belong to the resource: the
// user, the host (an S3 bucket), each path segment (a database, a bucket)
// and each query value but secret:NAME.
func urlWords(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var w []string
	if u.User != nil {
		w = append(w, u.User.Username())
	}
	w = append(w, u.Hostname())
	w = append(w, strings.Split(u.Path, "/")...)
	for _, vs := range u.Query() {
		for _, v := range vs {
			if !strings.HasPrefix(v, "secret:") {
				w = append(w, v)
			}
		}
	}
	return slices.DeleteFunc(w, func(x string) bool { return x == "" })
}

// nameByte is a byte of a name: letters, digits and . _ -.
func nameByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-'
}

// replace gives text with the old names that follow replaced, and the old
// names it keeps. A word runs over name bytes, and * and ? for patterns; a
// full stop or a question mark after it ends a sentence, and stars that
// close the ones before it (*name*, **name**) are emphasis, so they are
// not part of it.
func (t *nameText) replace(text string) (string, []keptWord) {
	var sb strings.Builder
	var kept []keptWord
	for i := 0; i < len(text); {
		if !nameByte(text[i]) {
			sb.WriteByte(text[i])
			i++
			continue
		}
		j := i
		for j < len(text) && (nameByte(text[j]) || text[j] == '*' || text[j] == '?') {
			j++
		}
		w := text[i:j]
		core := strings.TrimRight(w, ".?")
		for k := i - 1; k >= 0 && text[k] == '*' && strings.HasSuffix(core, "*"); k-- {
			core = strings.TrimRight(core[:len(core)-1], ".?")
		}
		// @NAME is a group, as in a target; user@host is not
		at := i > 0 && text[i-1] == '@' && (i == 1 || !nameByte(text[i-2]))
		to, why := t.word(core, at)
		if why != "" {
			kept = append(kept, keptWord{core, why})
		}
		if to != "" {
			w = to + w[len(core):]
		}
		sb.WriteString(w)
		i = j
	}
	return sb.String(), kept
}

// word is the new name of one word ("" when it stays) and, when it stays
// although it is an old name, why.
func (t *nameText) word(w string, at bool) (to, why string) {
	switch {
	case w == "":
		return "", ""
	case at:
		return t.groups[w], ""
	case strings.ContainsAny(w, "*?"):
		return t.pattern(w)
	}
	if to, ok := t.follow[w]; ok {
		if c, ok := t.inURL[w]; ok {
			return "", "also in the URL of conn " + c + ", where it may name a user, a bucket or a database"
		}
		return to, ""
	}
	return "", t.left[w]
}

// pattern is the new form of a pattern that starts with OLD, when it is
// safe: every server, conn and VPN it matches is renamed, and the new
// pattern matches no other. Then it matches exactly the same entries
// after the rename.
func (t *nameText) pattern(p string) (to, why string) {
	if t.old == "" || !strings.HasPrefix(p, t.old) || (t.grows && strings.HasPrefix(p, t.new)) {
		return "", ""
	}
	if _, err := path.Match(p, ""); err != nil {
		return "", ""
	}
	np := t.new + p[len(t.old):]
	matched := 0
	for _, n := range t.before {
		_, gone := t.renamed[n]
		if ok, _ := path.Match(p, n); ok {
			if !gone {
				return "", "a pattern that also matches " + n + ", which keeps its name"
			}
			matched++
		} else if ok, _ := path.Match(np, n); ok && !gone {
			return "", "after the rename, " + np + " would also match " + n
		}
	}
	if matched == 0 {
		return "", "a pattern that matches no server, conn or VPN"
	}
	return np, ""
}
