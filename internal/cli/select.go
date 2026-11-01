package cli

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Selectors pick hosts and conns together: `@prod` is everything in the
// prod group, servers and databases alike. Commands that look (list, test,
// group) use everything picked. Commands that act use what they can work
// with and report the rest in meta.skipped (docs/design/ux.md, section 2).

// selection is what a selector expression picked, each part sorted by name.
type selection struct {
	Hosts []*store.Host
	Conns []*store.Conn
}

// resolveSelection expands a selector expression ("@web,tag:prod,!web-2")
// over hosts and conns. It fails when nothing matches.
func resolveSelection(st *store.State, expr string) (selection, error) {
	type item struct {
		h *store.Host
		c *store.Conn
	}
	name := func(it item) string {
		if it.h != nil {
			return it.h.Name
		}
		return it.c.Name
	}
	items, err := resolveExpr(expr, func(sel string) ([]item, error) {
		var res []item
		hs, cs, err := matchSelector(st, sel)
		for _, h := range hs {
			res = append(res, item{h: h})
		}
		for _, c := range cs {
			res = append(res, item{c: c})
		}
		return res, err
	}, name)
	if err != nil {
		return selection{}, err
	}
	var sel selection
	for _, it := range items {
		if it.h != nil {
			sel.Hosts = append(sel.Hosts, it.h)
		} else {
			sel.Conns = append(sel.Conns, it.c)
		}
	}
	if len(items) == 0 {
		hint := "run `komando list` to see servers, conns, groups and tags"
		if s := closestSelector(st, expr); s != "" {
			hint = fmt.Sprintf("did you mean %q? (%s)", s, hint)
		}
		return sel, out.Errf(out.ExitNotFound, "TARGET_EMPTY", hint, "target %q matched nothing", expr)
	}
	return sel, nil
}

// resolveExpr applies a comma-separated selector expression ("a,b,!c") using
// match for each part. The result is sorted by name and may be empty.
func resolveExpr[T any](expr string, match func(sel string) ([]T, error), name func(T) string) ([]T, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, out.Usage("empty target")
	}
	include := map[string]T{}
	exclude := map[string]bool{}
	for _, raw := range strings.Split(expr, ",") {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			continue
		}
		neg := strings.HasPrefix(sel, "!")
		sel = strings.TrimPrefix(sel, "!")
		matched, err := match(sel)
		if err != nil {
			return nil, err
		}
		for _, it := range matched {
			if neg {
				exclude[name(it)] = true
			} else {
				include[name(it)] = it
			}
		}
	}
	var res []T
	for n, it := range include {
		if !exclude[n] {
			res = append(res, it)
		}
	}
	sort.Slice(res, func(i, j int) bool { return name(res[i]) < name(res[j]) })
	return res, nil
}

// matchSelector applies one selector (no commas, no "!") to hosts and conns.
func matchSelector(st *store.State, sel string) ([]*store.Host, []*store.Conn, error) {
	if k, ok := strings.CutPrefix(sel, "kind:"); ok {
		return matchKind(st, k)
	}
	if hs, ok := matchPattern(st.SortedHosts(), hostAttrs, sel); ok {
		cs, _ := matchPattern(st.SortedConns(), connAttrs, sel)
		return hs, cs, nil
	}
	if h, ok := st.Hosts[sel]; ok {
		return []*store.Host{h}, nil, nil
	}
	if c, ok := st.Conns[sel]; ok {
		return nil, []*store.Conn{c}, nil
	}
	if strings.Contains(sel, "@") {
		if h, err := sshx.ParseAdhoc(sel); err == nil {
			return []*store.Host{h}, nil, nil
		}
	}
	return nil, nil, targetNotFound(st, sel)
}

// matchKind picks by type: kind:host, a conn kind (kind:postgres) or the
// command a conn works with (kind:db, kind:cache, kind:storage).
func matchKind(st *store.State, k string) ([]*store.Host, []*store.Conn, error) {
	k = strings.ToLower(k)
	if k == "host" || k == "server" {
		return st.SortedHosts(), nil, nil
	}
	if k == "conn" {
		return nil, st.SortedConns(), nil
	}
	known := false
	for _, kd := range driver.Kinds() {
		known = known || kd.Name == k || kd.Family == k
	}
	if !known {
		return nil, nil, out.Usage("unknown kind %q: use host, conn, a conn kind (see `komando conn kinds`) or db, cache, storage", k)
	}
	var cs []*store.Conn
	for _, c := range st.SortedConns() {
		if c.Kind == k || connFamily(c) == k {
			cs = append(cs, c)
		}
	}
	return nil, cs, nil
}

// selAttrs is what pattern selectors look at; hosts and conns both have it.
type selAttrs struct {
	name   string
	groups []string
	tags   []string
	labels map[string]string
}

func hostAttrs(h *store.Host) selAttrs { return selAttrs{h.Name, h.Groups, h.Tags, h.Labels} }
func connAttrs(c *store.Conn) selAttrs { return selAttrs{c.Name, c.Groups, c.Tags, c.Labels} }

// matchPattern applies the pattern selectors (all, @group, tag:, label:,
// glob) to items. ok is false when sel is a plain name.
func matchPattern[T any](items []T, attrs func(T) selAttrs, sel string) (res []T, ok bool) {
	has := func(list []string, v string) bool {
		return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) })
	}
	var f func(a selAttrs) bool
	switch {
	case sel == "all" || sel == "*":
		f = func(selAttrs) bool { return true }
	case strings.HasPrefix(sel, "@"):
		f = func(a selAttrs) bool { return has(a.groups, sel[1:]) }
	case strings.HasPrefix(sel, "tag:"):
		f = func(a selAttrs) bool { return has(a.tags, sel[4:]) }
	case strings.HasPrefix(sel, "label:"):
		k, v, _ := strings.Cut(sel[6:], "=")
		f = func(a selAttrs) bool { return a.labels[k] == v }
	case strings.ContainsAny(sel, "*?["):
		f = func(a selAttrs) bool { ok, _ := path.Match(sel, a.name); return ok }
	default:
		return nil, false
	}
	for _, it := range items {
		if f(attrs(it)) {
			res = append(res, it)
		}
	}
	return res, true
}

// targetNotFound is the error for an unknown name, with a "did you mean"
// when a host, conn, group or tag is spelled almost the same.
func targetNotFound(st *store.State, sel string) error {
	var names []string
	for _, h := range st.SortedHosts() {
		names = append(names, h.Name)
	}
	for _, c := range st.SortedConns() {
		names = append(names, c.Name)
	}
	hint := "run `komando list` to see servers and conns"
	if s := closest(sel, names); s != "" {
		hint = fmt.Sprintf("did you mean %q? (%s)", s, hint)
	}
	return out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", hint, "no server or conn named %q", sel)
}

// closestSelector suggests a group or tag for a misspelled @group or tag:
// part of expr.
func closestSelector(st *store.State, expr string) string {
	groups, tags := map[string]bool{}, map[string]bool{}
	for _, h := range st.SortedHosts() {
		for _, g := range h.Groups {
			groups[g] = true
		}
		for _, t := range h.Tags {
			tags[t] = true
		}
	}
	for _, c := range st.SortedConns() {
		for _, g := range c.Groups {
			groups[g] = true
		}
		for _, t := range c.Tags {
			tags[t] = true
		}
	}
	keys := func(m map[string]bool) []string {
		var k []string
		for x := range m {
			k = append(k, x)
		}
		sort.Strings(k)
		return k
	}
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "!")
		if g, ok := strings.CutPrefix(part, "@"); ok {
			if s := closest(g, keys(groups)); s != "" {
				return "@" + s
			}
		}
		if t, ok := strings.CutPrefix(part, "tag:"); ok {
			if s := closest(t, keys(tags)); s != "" {
				return "tag:" + s
			}
		}
	}
	return ""
}

// closest returns the candidate within two edits of word, if any.
func closest(word string, candidates []string) string {
	best, bestD := "", 3
	for _, c := range candidates {
		if d := editDistance(strings.ToLower(word), strings.ToLower(c)); d < bestD {
			best, bestD = c, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// connFamily is the command a conn works with: db, cache or storage.
func connFamily(c *store.Conn) string {
	k, _ := driver.Lookup(c.Kind)
	return k.Family
}

// useFor says which command works with a target, for skip reasons and hints.
func useFor(h *store.Host, c *store.Conn) string {
	if h != nil {
		return "a server: use `komando exec` and the other server commands"
	}
	return fmt.Sprintf("a %s conn: use `komando %s`", c.Kind, connFamily(c))
}

// renameNotFound keeps the older, more specific not-found codes for
// commands that work with one type only.
func renameNotFound(err error, code string) error {
	if e := toErr(err); e.Code == "TARGET_NOT_FOUND" {
		e.Code = code
		return e
	}
	return err
}

// resolveTargets is resolveSelection for commands that work on servers.
// Conns the selector picked are reported as skipped.
func resolveTargets(st *store.State, expr string) ([]*store.Host, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return nil, renameNotFound(err, "HOST_NOT_FOUND")
	}
	if len(sel.Hosts) == 0 {
		return nil, noMatch(expr, "servers", nil, sel.Conns)
	}
	for _, c := range sel.Conns {
		out.P.Skip(out.Skipped{Name: c.Name, Kind: c.Kind, Reason: useFor(nil, c)})
	}
	return sel.Hosts, nil
}

// resolveConns is resolveSelection for commands that work on any conn.
// Servers the selector picked are reported as skipped.
func resolveConns(st *store.State, expr string) ([]*store.Conn, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return nil, renameNotFound(err, "CONN_NOT_FOUND")
	}
	if len(sel.Conns) == 0 {
		return nil, noMatch(expr, "conns", sel.Hosts, nil)
	}
	for _, h := range sel.Hosts {
		out.P.Skip(out.Skipped{Name: h.Name, Kind: "host", Reason: useFor(h, nil)})
	}
	return sel.Conns, nil
}

// noMatch is the error when a selector picked targets, but none this
// command can work with. The hint names the command that can.
func noMatch(expr, want string, hs []*store.Host, cs []*store.Conn) error {
	var picked []string
	hint := ""
	for _, h := range hs {
		picked = append(picked, h.Name+" (server)")
		if hint == "" {
			hint = h.Name + " is " + useFor(h, nil)
		}
	}
	for _, c := range cs {
		picked = append(picked, fmt.Sprintf("%s (%s)", c.Name, c.Kind))
		if hint == "" {
			hint = c.Name + " is " + useFor(nil, c)
		}
	}
	return out.Errf(out.ExitNotFound, "NO_MATCHING_TARGETS", hint,
		"target %q picked no %s, only: %s", expr, want, strings.Join(picked, ", "))
}

// targetNames turns a --target filter into the names it picks. Filters
// also look at history (audit, jobs) of servers and conns removed since, so
// when the selector matches nothing in the inventory its parts are used as
// plain names.
func targetNames(st *store.State, expr string) map[string]bool {
	names := map[string]bool{}
	if sel, err := resolveSelection(st, expr); err == nil {
		for _, h := range sel.Hosts {
			names[h.Name] = true
		}
		for _, c := range sel.Conns {
			names[c.Name] = true
		}
		return names
	}
	for _, n := range strings.Split(expr, ",") {
		if n = strings.TrimSpace(n); n != "" && !strings.HasPrefix(n, "!") {
			names[n] = true
		}
	}
	return names
}

// viaChain splits a --via value ("vpn1,bastion") into its steps.
func viaChain(via string) []string {
	var steps []string
	for _, s := range strings.Split(via, ",") {
		if s = strings.TrimSpace(s); s != "" {
			steps = append(steps, s)
		}
	}
	return steps
}

// singleHost resolves a selector that must pick exactly one server.
func singleHost(st *store.State, expr string) (*store.Host, error) {
	hs, err := resolveTargets(st, expr)
	if err != nil {
		return nil, err
	}
	if len(hs) != 1 {
		return nil, out.Usage("target %q matched %d servers; this command needs exactly one", expr, len(hs))
	}
	return hs[0], nil
}

// singleConn resolves a selector that must pick exactly one conn of the
// family the command works with (db, cache, storage). Other targets the
// selector picked are reported as skipped.
func singleConn(st *store.State, expr, family string) (*store.Conn, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return nil, renameNotFound(err, "CONN_NOT_FOUND")
	}
	var match []*store.Conn
	var skip []out.Skipped
	for _, c := range sel.Conns {
		if connFamily(c) == family {
			match = append(match, c)
		} else {
			skip = append(skip, out.Skipped{Name: c.Name, Kind: c.Kind, Reason: useFor(nil, c)})
		}
	}
	for _, h := range sel.Hosts {
		skip = append(skip, out.Skipped{Name: h.Name, Kind: "host", Reason: useFor(h, nil)})
	}
	if len(match) == 0 {
		return nil, noMatch(expr, family+" conns", sel.Hosts, sel.Conns)
	}
	if len(match) != 1 {
		names := make([]string, len(match))
		for i, c := range match {
			names[i] = c.Name
		}
		return nil, out.Usage("target %q matched %d %s conns (%s); this command needs exactly one",
			expr, len(match), family, strings.Join(names, ", "))
	}
	for _, s := range skip {
		out.P.Skip(s)
	}
	t, err := driver.Parse(match[0].URL)
	if err != nil {
		return nil, err
	}
	if err := t.Need(family); err != nil {
		return nil, err
	}
	return match[0], nil
}
