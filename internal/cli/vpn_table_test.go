package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
)

// vpnTableLeaves are the built leaves of the vpn type, by key.
func vpnTableLeaves(t *testing.T) []capability.Leaf {
	t.Helper()
	var ls []capability.Leaf
	for _, l := range capability.All() {
		if l.Type == "vpn" && l.State == capability.Built {
			ls = append(ls, l)
		}
	}
	if len(ls) == 0 {
		t.Fatal("no vpn leaf is built")
	}
	return ls
}

// Every kind of VPN has all ten verbs, and a handler for each.
func TestVpnEveryKindHasEveryVerb(t *testing.T) {
	want := []string{"add", "edit", "list", "remove", "rename", "show", "start", "status", "stop", "test"}
	kinds := capability.Children("vpn")
	if len(kinds) != 14 {
		t.Fatalf("vpn has %d kinds: %v", len(kinds), kinds)
	}
	for _, p := range kinds {
		var got []string
		for _, l := range vpnTableLeaves(t) {
			if l.Provider == p {
				got = append(got, l.Verb)
				if handlers[l.Key] == nil {
					t.Errorf("%s: no handler", l.Key)
				}
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("vpn %s has the verbs %v, want %v", p, got, want)
		}
	}
}

// TestVpnProvidersCarryEqualTableEntries pins the all-carriers rule for
// vpn: the leaves of one verb carry the same entry in every table keyed by
// command ID or path (idTables), whichever kind they sit under.
func TestVpnProvidersCarryEqualTableEntries(t *testing.T) {
	tables := idTables()
	type entry struct {
		key  safetyKey
		have []bool // per table: has an entry
		vals []any
	}
	byVerb := map[string]map[string]entry{}
	for _, l := range vpnTableLeaves(t) {
		id := strings.Join(l.Key.Path(), ".")
		e := entry{key: cmdKeys[id]}
		for _, tb := range tables {
			v, ok := tb.get(id)
			e.have, e.vals = append(e.have, ok), append(e.vals, v)
		}
		if want := (safetyKey{l.Type, l.Area, l.Verb}); e.key != want {
			t.Errorf("%s: cmdKeys has %v, the leaf's key is %v", id, e.key, want)
		}
		if localReads[id] != l.LocalRead || leavesHome[id] != l.LeavesHome {
			t.Errorf("%s: localReads %v, leavesHome %v; the leaf says %v, %v", id, localReads[id], leavesHome[id], l.LocalRead, l.LeavesHome)
		}
		if byVerb[l.Verb] == nil {
			byVerb[l.Verb] = map[string]entry{}
		}
		byVerb[l.Verb][l.Provider] = e
	}
	for verb, byKind := range byVerb {
		var first string
		for p, e := range byKind {
			if first == "" {
				first = p
				continue
			}
			f := byKind[first]
			if e.key != f.key || !slices.Equal(e.have, f.have) {
				t.Errorf("vpn %s: %s carries %v %v, %s carries %v %v", verb, p, e.key, e.have, first, f.key, f.have)
				continue
			}
			for i, tb := range tables {
				if e.have[i] && !sameEntry(e.vals[i], f.vals[i]) {
					t.Errorf("vpn %s: %s and %s carry different entries in %s", verb, p, first, tb.name)
				}
			}
		}
	}
	// what today's vpn commands had in the tables, every kind keeps
	for _, l := range vpnTableLeaves(t) {
		id := strings.Join(l.Key.Path(), ".")
		_, noNet := gateNoNetwork[id]
		if want := slices.Contains([]string{"list", "show", "status", "test"}, l.Verb); noNet != want {
			t.Errorf("%s: gateNoNetwork has an entry: %v, want %v", id, noNet, want)
		}
	}
}

// The table and the body agree on every option and default: the leaf
// types an option the body has (a credential is the body's password-ref),
// and an option that is not typed falls back to the body's default.
func TestVpnBodyOptionsMatchTable(t *testing.T) {
	zero := func(s string) bool { return s == "" || s == "0" || s == "false" || s == "0s" || s == "[]" }
	for _, l := range vpnTableLeaves(t) {
		body := vpnBodies[l.Verb](l.Provider)
		for _, o := range l.Options {
			if o.Generated {
				continue // komando makes the value; the body is never given it
			}
			name := o.Name
			switch name {
			case "credential":
				name = "password-ref"
			case "psk-credential":
				name = "psk-ref"
			}
			f := body.Flags().Lookup(name)
			if f == nil {
				t.Errorf("%s --%s: the body has no such flag", l.Key, o.Name)
				continue
			}
			if o.Kind == capability.Bytes || o.Kind == capability.Duration {
				continue
			}
			if f.DefValue != o.Default && !(zero(f.DefValue) && zero(o.Default)) {
				t.Errorf("%s --%s: the table's default is %q, the body's %q", l.Key, o.Name, o.Default, f.DefValue)
			}
		}
	}
}

// The first line of each kind's add example is a command that works: it
// runs as a dry run with the files and names it needs.
func TestVpnAddExamplesRun(t *testing.T) {
	invHome(t)
	wg, ovpn := vpnSecretFiles(t)
	for _, p := range capability.Children("vpn") {
		l, _ := capability.Find(capability.Key{Type: "vpn", Provider: p, Verb: "add"})
		line, _, _ := strings.Cut(l.Example, "\n")
		words := splitExample(strings.TrimSpace(line))
		if len(words) < 5 || words[0] != "komando" || words[1] != "vpn" || words[2] != p || words[3] != "add" {
			t.Fatalf("%s: the example is %q", p, line)
		}
		args := slices.Clone(words[1:])
		for i, w := range args {
			switch {
			case w == "--config" && p == "wireguard":
				args[i+1] = wg("1")
			case w == "--config":
				args[i+1] = ovpn("1")
			}
		}
		mustRun(t, append([]string{"--dry-run"}, args...)...)
	}
}

// splitExample splits an example line into words, keeping "Corp VPN" whole.
func splitExample(line string) []string {
	var words []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

// A kind takes its own flags: another kind's flag is a usage error, and so
// is a flag the kind needs left out.
func TestVpnKindsTakeTheirOwnFlags(t *testing.T) {
	invHome(t)
	wg, _ := vpnSecretFiles(t)
	wantCode(t, "USAGE", "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080", "--portal", "vpn.example.com")
	wantCode(t, "USAGE", "vpn", "wireguard", "add", "lab", "--config", wg("1"), "--user", "alice")
	wantCode(t, "USAGE", "vpn", "socks", "add", "lab")
	wantCode(t, "USAGE", "vpn", "globalprotect", "add", "lab")
	wantCode(t, "USAGE", "vpn", "socks", "edit", "lab", "--portal", "vpn.example.com")
	for _, flag := range []string{"portal", "server", "ca"} {
		l, _ := capability.Find(capability.Key{Type: "vpn", Provider: "socks", Verb: "add"})
		if _, has := l.Option(flag); has {
			t.Errorf("vpn socks add has --%s", flag)
		}
	}
	if !vpnTakes("l2tp", "legacy-crypto") || vpnTakes("ipsec", "allow-pap") || vpnTakes("wireguard", "credential") {
		t.Error("vpnTakes reads the table wrongly")
	}
	if got := vpnKindsTaking("ask-psk"); !slices.Equal(got, []string{"l2tp", "ipsec", "ikev2"}) {
		t.Errorf("kinds that take --ask-psk: %v", got)
	}
}

// The kind in the path is the kind the VPN was saved with: another kind's
// path is WRONG_KIND, with the path that fits.
func TestVpnWrongKind(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "vpn", "socks", "add", "lab2", "--proxy-address", "127.0.0.1:1081", "--group", "office")
	for _, args := range [][]string{
		{"vpn", "wireguard", "show", "lab"}, {"vpn", "wireguard", "start", "lab"}, {"vpn", "wireguard", "stop", "lab"},
		{"vpn", "wireguard", "status", "lab"}, {"vpn", "wireguard", "rename", "lab", "lab9"}, {"vpn", "wireguard", "edit", "lab", "--notes", "x"},
		{"vpn", "wireguard", "remove", "lab"}, {"vpn", "wireguard", "test", "lab"}, {"vpn", "wireguard", "remove", "@office"},
	} {
		e := wantCode(t, "WRONG_KIND", args...)
		if !strings.Contains(e.Hint, "komando vpn socks "+args[2]) {
			t.Errorf("%v: the hint is %q", args, e.Hint)
		}
	}
	if d := mustRun(t, "vpn", "socks", "show", "lab"); d["vpn"] == nil {
		t.Errorf("show: %v", d)
	}
	// a name that is no VPN is the command's to say
	wantCode(t, "TARGET_NOT_FOUND", "vpn", "wireguard", "show", "nosuch")
}

// vpn KIND list and status show the VPNs of that kind only.
func TestVpnListAndStatusOfOneKind(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1")
	mustRun(t, "vpn", "proxy", "add", "gate", "--proxy-address", "127.0.0.1:2")
	if d := mustRun(t, "vpn", "socks", "list"); d["count"] != float64(1) {
		t.Errorf("socks list: %v", d)
	}
	if d := mustRun(t, "vpn", "proxy", "list"); d["count"] != float64(1) {
		t.Errorf("proxy list: %v", d)
	}
	if d := mustRun(t, "vpn", "socks", "status"); len(d["vpns"].([]any)) != 1 {
		t.Errorf("socks status: %v", d)
	}
	if d := mustRun(t, "vpn", "socks", "status", "lab"); len(d["vpns"].([]any)) != 1 {
		t.Errorf("socks status lab: %v", d)
	}
	if d := mustRun(t, "vpn", "wireguard", "status"); len(d["vpns"].([]any)) != 0 {
		t.Errorf("wireguard status: %v", d)
	}
}

// The form hints of the vpn commands are made when a command asks for
// them: none is in the table of hints at start, and every kind and verb
// has one.
func TestVpnHintsAreMadeWhenAsked(t *testing.T) {
	for key := range formHints {
		if strings.HasPrefix(key, "vpn ") {
			t.Errorf("formHints has %q at start", key)
		}
	}
	for _, l := range vpnTableLeaves(t) {
		key := strings.Join(l.Key.Path(), " ")
		h, ok := hintOf(key)
		if !ok {
			t.Errorf("%s has no hint", key)
			continue
		}
		if l.Verb == "add" && h.form == nil {
			t.Errorf("%s: the add hint has no form", key)
		}
		for _, f := range h.flags {
			if _, has := l.Option(f.name); !has {
				t.Errorf("%s: the hint asks --%s, which the leaf does not have", key, f.name)
			}
		}
	}
	if _, ok := hintOf("vpn nosuchkind add"); ok {
		t.Error("a hint for a kind that does not exist")
	}
}
