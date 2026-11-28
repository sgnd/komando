package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// The rename engine behind `credential key rename` and `group rename`:
// renames done together, in one step. The inventory is written once, after
// every check passed, or not at all. Every reference follows (the key a
// server uses, group membership).

// renameKinds are the kinds a rename covers, in the order it reports them.
var renameKinds = []string{"key", "group"}

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
// from the locked state, applyRenames changes the state, and the state is
// saved last. When anything fails (a check, the save), the state is not
// saved, so nothing changes. Under --dry-run only the plan runs.
func renameTx(cl *call, plan func(s *store.State) (renameSet, renameOpts, error)) (renameResult, error) {
	var res renameResult
	// the questions first, outside the store's lock: plan and applyRenames
	// change only the copy
	if err := askFirst(cl, func(s *store.State) error {
		set, opts, err := plan(s)
		if err != nil {
			return err
		}
		_, err = applyRenames(cl, s, set, opts)
		return err
	}); err != nil {
		return renameResult{}, err
	}
	err := storeUpdate(cl, func(s *store.State) error {
		set, opts, err := plan(s)
		if err != nil {
			return err
		}
		res, err = applyRenames(cl, s, set, opts)
		return err
	})
	return res, err
}

// applyRenames checks set against s and, when every check passes, renames
// in s: the entries, then every reference to them.
func applyRenames(cl *call, s *store.State, set renameSet, opts renameOpts) (renameResult, error) {
	res := renameResult{Action: mvVerb(cl), Renamed: map[string][]renamePair{}, Protected: []string{}, Updated: []renameRef{}, Moved: []renamePair{}}
	if set.size() == 0 {
		res.Action = "unchanged"
		return res, nil
	}
	if err := checkRenameSet(cl, s, set); err != nil {
		return res, err
	}
	res.Protected = renameProtected(s, set)
	if len(res.Protected) > 0 && opts.guard != nil {
		if err := opts.guard(res.Protected); err != nil {
			return res, err
		}
	}
	rw := newRefRewriter(set, opts, &res)
	rw.renameEntries(s)
	res.Count = set.size()
	rw.rewrite(s)
	return res, nil
}

// renameProtected is the protected servers and conns a rename changes: a
// group of theirs renamed.
func renameProtected(s *store.State, set renameSet) []string {
	prot := []string{}
	for _, h := range s.SortedHosts() {
		if h.Protected && inRenamedGroup(set["group"], h.Groups) {
			prot = append(prot, "host "+h.Name)
		}
	}
	for _, c := range s.SortedConns() {
		if c.Protected && inRenamedGroup(set["group"], c.Groups) {
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
	res     *renameResult
	now     time.Time
	touched bool // the entry being rewritten changed
}

func newRefRewriter(rs renameSet, opts renameOpts, res *renameResult) *refRewriter {
	return &refRewriter{rs: rs, opts: opts, res: res, now: time.Now().UTC()}
}

// renameEntries gives every entry in the set its new name.
func (w *refRewriter) renameEntries(s *store.State) {
	for _, k := range renameKinds {
		for _, from := range slices.Sorted(maps.Keys(w.rs[k])) {
			p := renamePair{From: from, To: w.rs[k][from]}
			if k == "key" {
				w.renameKey(s, from, p.To)
			}
			w.res.Renamed[k] = append(w.res.Renamed[k], p)
		}
	}
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
		w.touched = false
		if to, ok := w.rs["key"][h.Key]; ok {
			w.change("host "+h.Name, "key", &h.Key, to)
		}
		w.groups("host "+h.Name, &h.Groups)
		if w.touched {
			h.UpdatedAt = w.now
		}
	}
	for _, c := range s.SortedConns() {
		w.touched = false
		w.groups("conn "+c.Name, &c.Groups)
		if w.touched {
			c.UpdatedAt = w.now
		}
	}
	for _, v := range s.SortedVpns() {
		w.touched = false
		w.groups("vpn "+v.Name, &v.Groups)
		if w.touched {
			v.UpdatedAt = w.now
		}
	}
}

// renameChecker collects what stops a rename.
type renameChecker struct {
	cl      *call // the call it works for
	s       *store.State
	groups  []string // every group as written
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
	c := &renameChecker{cl: cl, s: s, groups: slices.Sorted(maps.Keys(allGroups(s).Groups))}
	for _, k := range renameKinds {
		news := map[string]string{} // new name (lower case for groups) -> old
		for _, from := range slices.Sorted(maps.Keys(set[k])) {
			to := set[k][from]
			if err := c.check(k, from, to); err != nil {
				return err
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
