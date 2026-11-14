package cli

import (
	"fmt"
	"net"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Selectors pick hosts and conns together: `@prod` is everything in the
// prod group, servers and databases alike. Commands that look (list, test,
// group) use everything picked. Commands that act use what they can work
// with and report the rest in meta.skipped (docs/design/principles.md, section 3).

// selection is what a selector expression picked, each part sorted by name.
type selection struct {
	Hosts []*store.Host
	Conns []*store.Conn
	Vpns  []*store.Vpn
}

// resolveSelection expands a selector expression ("@web,tag:prod,!web-2")
// over hosts and conns. It fails when nothing matches.
func resolveSelection(cl *call, st *store.State, expr string) (selection, error) {
	type item struct {
		h *store.Host
		c *store.Conn
		v *store.Vpn
	}
	name := func(it item) string {
		switch {
		case it.h != nil:
			return it.h.Name
		case it.c != nil:
			return it.c.Name
		}
		return it.v.Name
	}
	items, err := resolveExpr(expr, func(sel string) ([]item, error) {
		var res []item
		m, err := matchSelector(cl, st, sel)
		for _, h := range m.Hosts {
			res = append(res, item{h: h})
		}
		for _, c := range m.Conns {
			res = append(res, item{c: c})
		}
		for _, v := range m.Vpns {
			res = append(res, item{v: v})
		}
		return res, err
	}, name)
	if err != nil {
		return selection{}, err
	}
	var sel selection
	for _, it := range items {
		switch {
		case it.h != nil:
			sel.Hosts = append(sel.Hosts, it.h)
		case it.c != nil:
			sel.Conns = append(sel.Conns, it.c)
		default:
			sel.Vpns = append(sel.Vpns, it.v)
		}
	}
	if len(items) == 0 {
		hint := "run `komando list` to see servers, conns, groups and tags"
		near := ""
		if len(st.Hosts)+len(st.Conns)+len(st.Vpns) == 0 {
			hint = "your list is empty: add a server with `komando host add web1 deploy@10.0.0.5`, or import ~/.ssh/config with `komando import ssh-config`"
		} else {
			near = closestSelector(st, expr)
		}
		msg := fmt.Sprintf("target %q matched nothing", expr)
		if e := strings.TrimSpace(expr); !strings.Contains(e, ",") {
			if gr, ok := strings.CutPrefix(e, "@"); ok {
				msg = fmt.Sprintf("no group named %q", gr)
			} else if t, ok := strings.CutPrefix(e, "tag:"); ok {
				msg = fmt.Sprintf("nothing has the tag %q", t)
			}
		}
		e := out.Errf(out.ExitNotFound, "TARGET_EMPTY", hint, "%s", msg)
		if near != "" {
			suggest(cl, e, strings.TrimSpace(expr), near)
		}
		return sel, e
	}
	notePersonal(cl, st, sel.Hosts, sel.Conns)
	return sel, nil
}

// resolveExpr applies a comma-separated selector expression ("a,b,!c") using
// match for each part. The result is sorted by name and may be empty.
func resolveExpr[T any](expr string, match func(sel string) ([]T, error), name func(T) string) ([]T, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, out.Usage("empty target")
	}
	if strings.HasPrefix(expr, "!") {
		expr = "all," + expr // "!web1" means everything but web1
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

// matchSelector applies one selector (no commas, no "!") to hosts, conns
// and VPNs.
func matchSelector(cl *call, st *store.State, sel string) (selection, error) {
	if k, ok := strings.CutPrefix(sel, "kind:"); ok {
		return matchKind(st, k)
	}
	if o, ok := strings.CutPrefix(sel, "os:"); ok {
		return matchOS(st, o)
	}
	if h := bracketedAdhoc(sel); h != nil { // [2001:db8::1] is an address, not a glob
		return selection{Hosts: []*store.Host{h}}, nil
	}
	if hs, ok := matchPattern(st.SortedHosts(), hostAttrs, sel); ok {
		cs, _ := matchPattern(st.SortedConns(), connAttrs, sel)
		vs, _ := matchPattern(st.SortedVpns(), vpnAttrs, sel)
		return selection{hs, cs, vs}, nil
	}
	if h, ok := st.Hosts[sel]; ok {
		return selection{Hosts: []*store.Host{h}}, nil
	}
	if c, ok := st.Conns[sel]; ok {
		return selection{Conns: []*store.Conn{c}}, nil
	}
	if v, ok := st.Vpns[sel]; ok {
		return selection{Vpns: []*store.Vpn{v}}, nil
	}
	if n, ok := foldMatch(sel, allNames(st)); ok { // Web1 for web1
		return matchSelector(cl, st, n)
	}
	if looksAdhoc(sel) {
		if h, err := sshx.ParseAdhoc(sel); err == nil && validPort(h.Port) == nil {
			h.Address = normAddr(h.Address)
			return selection{Hosts: []*store.Host{h}}, nil
		}
	}
	return selection{}, targetNotFound(cl, st, sel)
}

// bracketedAdhoc is the ad-hoc server an IPv6 address in brackets names
// ([2001:db8::1], root@[::1]:2222), or nil.
func bracketedAdhoc(sel string) *store.Host {
	i, j := strings.IndexByte(sel, '['), strings.IndexByte(sel, ']')
	if i < 0 || j < i || net.ParseIP(sel[i+1:j]) == nil {
		return nil
	}
	h, err := sshx.ParseAdhoc(sel)
	if err != nil || validPort(h.Port) != nil {
		return nil
	}
	h.Address = normAddr(h.Address)
	return h
}

// looksAdhoc: user@host[:port], or an IP address or host:port without a
// user (the login user is then the default one).
func looksAdhoc(sel string) bool {
	if strings.Contains(sel, "@") {
		return true
	}
	if net.ParseIP(strings.Trim(sel, "[]")) != nil {
		return true
	}
	_, port, err := net.SplitHostPort(sel)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

// allNames are the names of every server, conn and VPN.
func allNames(st *store.State) []string {
	var names []string
	for _, h := range st.SortedHosts() {
		names = append(names, h.Name)
	}
	for _, c := range st.SortedConns() {
		names = append(names, c.Name)
	}
	for _, v := range st.SortedVpns() {
		names = append(names, v.Name)
	}
	return names
}

// matchKind picks by type: kind:host, kind:conn, kind:vpn, a conn kind
// (kind:postgres), the command a conn works with (kind:db, kind:cache,
// kind:storage) or a VPN kind (kind:wireguard).
func matchKind(st *store.State, k string) (selection, error) {
	k = strings.ToLower(k)
	switch k {
	case "host", "server":
		return selection{Hosts: st.SortedHosts()}, nil
	case "conn":
		return selection{Conns: st.SortedConns()}, nil
	case "vpn":
		return selection{Vpns: st.SortedVpns()}, nil
	}
	if _, ok := netx.Kinds[k]; ok {
		var vs []*store.Vpn
		for _, v := range st.SortedVpns() {
			if v.Kind == k {
				vs = append(vs, v)
			}
		}
		return selection{Vpns: vs}, nil
	}
	known := false
	var families []string
	for _, kd := range driver.Kinds() {
		known = known || kd.Name == k || kd.Family == k
		if !slices.Contains(families, kd.Family) {
			families = append(families, kd.Family)
		}
	}
	if !known {
		slices.Sort(families)
		return selection{}, out.Usage("unknown kind %q: use host, conn, vpn, a conn kind (see `komando conn kinds`) or %s", k, strings.Join(families, ", "))
	}
	var cs []*store.Conn
	for _, c := range st.SortedConns() {
		if c.Kind == k || connFamily(c) == k {
			cs = append(cs, c)
		}
	}
	return selection{Conns: cs}, nil
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
func vpnAttrs(v *store.Vpn) selAttrs   { return selAttrs{v.Name, v.Groups, v.Tags, v.Labels} }

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
		k, v, withValue := strings.Cut(sel[6:], "=")
		f = func(a selAttrs) bool {
			got, has := a.labels[k]
			if !withValue { // label:env = everything that has the label
				return has
			}
			return has && got == v
		}
	case strings.ContainsAny(sel, "*?["):
		pat := strings.ToLower(sel) // names match in any case, globs too
		f = func(a selAttrs) bool { ok, _ := path.Match(pat, strings.ToLower(a.name)); return ok }
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
func targetNotFound(cl *call, st *store.State, sel string) error {
	names := allNames(st)
	e := out.Errf(out.ExitNotFound, "TARGET_NOT_FOUND", "run `komando list` to see servers, conns and VPNs", "no server, conn or VPN named %q", sel)
	if s := closest(sel, names); s != "" {
		suggest(cl, e, sel, s)
	}
	return e
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
	for _, v := range st.SortedVpns() {
		for _, g := range v.Groups {
			groups[g] = true
		}
		for _, t := range v.Tags {
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

// editDistance counts the edits between a and b; swapping two neighbours
// counts as one (wbe -> web), as people type.
func editDistance(a, b string) int {
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
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

// skipVpns reports the VPNs a selector picked; no command acts on a VPN
// directly, they are used through --via.
func skipVpns(cl *call, vs []*store.Vpn) {
	for _, v := range vs {
		cl.out.Skip(out.Skipped{Name: v.Name, Kind: "vpn", Reason: "a VPN: use it in a --via path"})
	}
}

// renameNotFound gives a command that works with one type only its own,
// more specific not-found code.
func renameNotFound(err error, code string) error {
	if e := toErr(err); e.Code == "TARGET_NOT_FOUND" {
		e.Code = code
		return e
	}
	return err
}

// resolveTargets is resolveSelection for commands that work on servers.
// Conns the selector picked are reported as skipped.
func resolveTargets(cl *call, st *store.State, expr string) ([]*store.Host, error) {
	sel, err := resolveSelection(cl, st, expr)
	if err != nil {
		return nil, renameNotFound(err, "HOST_NOT_FOUND")
	}
	if len(sel.Hosts) == 0 {
		return nil, noMatch(expr, "servers", selection{Conns: sel.Conns, Vpns: sel.Vpns})
	}
	for _, c := range sel.Conns {
		cl.out.Skip(out.Skipped{Name: c.Name, Kind: c.Kind, Reason: useFor(nil, c)})
	}
	skipVpns(cl, sel.Vpns)
	return sel.Hosts, nil
}

// noMatch is the error when a selector picked targets, but none this
// command can work with. The hint names the command that can.
func noMatch(expr, want string, sel selection) *out.Error {
	var picked []string
	hint := ""
	for _, h := range sel.Hosts {
		picked = append(picked, h.Name+" (server)")
		if hint == "" {
			hint = h.Name + " is " + useFor(h, nil)
		}
	}
	for _, c := range sel.Conns {
		picked = append(picked, fmt.Sprintf("%s (%s)", c.Name, c.Kind))
		if hint == "" {
			hint = c.Name + " is " + useFor(nil, c)
		}
	}
	for _, v := range sel.Vpns {
		picked = append(picked, v.Name+" (vpn)")
		if hint == "" {
			hint = v.Name + " is a VPN: use it in a --via path"
		}
	}
	return out.Errf(out.ExitNotFound, "NO_MATCHING_TARGETS", hint,
		"target %q picked no %s, only: %s", expr, want, strings.Join(picked, ", "))
}

// targetNames turns a --target filter into the names it picks. Filters
// also look at history (audit, jobs) of servers and conns removed since, so
// when the selector matches nothing in the inventory its parts are used as
// plain names.
func targetNames(cl *call, st *store.State, expr string) map[string]bool {
	names := map[string]bool{}
	if sel, err := resolveSelection(cl, st, expr); err == nil {
		for _, h := range sel.Hosts {
			names[h.Name] = true
		}
		for _, c := range sel.Conns {
			names[c.Name] = true
		}
		for _, v := range sel.Vpns {
			names[v.Name] = true
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
func singleHost(cl *call, st *store.State, expr string) (*store.Host, error) {
	hs, err := resolveTargets(cl, st, expr)
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
func singleConn(cl *call, st *store.State, expr, family string) (*store.Conn, error) {
	sel, err := resolveSelection(cl, st, expr)
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
		return nil, noMatch(expr, family+" conns", sel)
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
		cl.out.Skip(s)
	}
	skipVpns(cl, sel.Vpns)
	t, err := driver.Parse(match[0].URL)
	if err != nil {
		return nil, err
	}
	if err := t.Need(family); err != nil {
		return nil, err
	}
	return match[0], nil
}

// matchOS picks servers by their OS: os:windows, or os:linux for every
// other server (Linux and the other Unixes).
func matchOS(st *store.State, o string) (selection, error) {
	o = strings.ToLower(o)
	if o != store.OSWindows && o != "linux" {
		return selection{}, out.Usage("unknown OS %q: use os:windows or os:linux", o)
	}
	var hs []*store.Host
	for _, h := range st.SortedHosts() {
		if osAttr(h) == o {
			hs = append(hs, h)
		}
	}
	return selection{Hosts: hs}, nil
}
