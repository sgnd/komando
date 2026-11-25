package inventory

import (
	"slices"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// The rules for what goes into the inventory, pinned before they move to
// internal/inventory: a name, a login name, a port, a label, a --via path
// and the family of a conn. The messages are not pinned here, only what is
// accepted and what is refused.
func TestInventoryRules(t *testing.T) {
	t.Run("a name", func(t *testing.T) {
		for _, n := range []string{"web1", "web-1", "a.b_c", "9lives"} {
			if err := ValidName("host", n); err != nil {
				t.Errorf("ValidName(host, %q) = %v, want nil", n, err)
			}
		}
		for _, n := range []string{"", "-x", "bad name", "a/b", "x:y"} {
			if ValidName("host", n) == nil {
				t.Errorf("ValidName(host, %q) = nil, want an error", n)
			}
		}
		for _, kind := range []string{"host", "conn", "vpn"} {
			if ValidName(kind, "ALL") == nil {
				t.Errorf("ValidName(%s, ALL) = nil: all means everything as a target", kind)
			}
		}
		if err := ValidName("secret", "all"); err != nil {
			t.Errorf("ValidName(secret, all) = %v, want nil: only targets reserve all", err)
		}
	})
	t.Run("a login name", func(t *testing.T) {
		for _, u := range []string{"deploy", "_svc", "a.b-c", "user@dom", "ci$"} {
			if err := ValidUser(u); err != nil {
				t.Errorf("ValidUser(%q) = %v, want nil", u, err)
			}
		}
		for _, u := range []string{"", "a b", "-x", "a;b"} {
			if ValidUser(u) == nil {
				t.Errorf("ValidUser(%q) = nil, want an error", u)
			}
		}
	})
	t.Run("a port", func(t *testing.T) {
		for _, p := range []int{0, 1, 22, 65535} {
			if err := ValidPort(p); err != nil {
				t.Errorf("ValidPort(%d) = %v, want nil", p, err)
			}
		}
		for _, p := range []int{-1, 65536} {
			if ValidPort(p) == nil {
				t.Errorf("ValidPort(%d) = nil, want an error", p)
			}
		}
	})
	t.Run("a label", func(t *testing.T) {
		if err := ValidLabelName("group", "prod-eu"); err != nil {
			t.Errorf("ValidLabelName(group, prod-eu) = %v", err)
		}
		for _, n := range []string{"", "bad name", "a,b"} {
			if ValidLabelName("tag", n) == nil {
				t.Errorf("ValidLabelName(tag, %q) = nil, want an error", n)
			}
		}
		if err := CheckLabels([]string{"web"}, []string{"prod"}, map[string]string{"env": "eu"}); err != nil {
			t.Errorf("CheckLabels(valid) = %v", err)
		}
		for name, args := range map[string]struct {
			g, t []string
			l    map[string]string
		}{
			"a bad group": {g: []string{"bad name"}},
			"a bad tag":   {t: []string{"a b"}},
			"a bad key":   {l: map[string]string{"a b": "x"}},
			"a comma":     {l: map[string]string{"k": "a,b"}},
			"a control":   {l: map[string]string{"k": "a\x01b"}},
		} {
			if CheckLabels(args.g, args.t, args.l) == nil {
				t.Errorf("CheckLabels with %s = nil, want an error", name)
			}
		}
		if !HasControl("a\x01b") || !HasControl("a\x7fb") || HasControl("ab") {
			t.Errorf("HasControl is wrong for a control character, DEL and plain text")
		}
	})
	t.Run("a via path", func(t *testing.T) {
		if got, want := ViaChain(" vpn1, bastion ,,web"), []string{"vpn1", "bastion", "web"}; !slices.Equal(got, want) {
			t.Errorf("ViaChain = %v, want %v", got, want)
		}
		if got := ViaChain(""); len(got) != 0 {
			t.Errorf("ViaChain(empty) = %v, want nothing", got)
		}
		st := &store.State{Hosts: map[string]*store.Host{
			"a": {Name: "a", Via: "b,c"}, "b": {Name: "b", Via: "a"}, "c": {Name: "c"},
		}}
		if got, want := WaySteps(st, "a", map[string]bool{}), []string{"a", "b", "c"}; !slices.Equal(got, want) {
			t.Errorf("WaySteps(a) = %v, want %v (a cycle is cut, each name once)", got, want)
		}
	})
	t.Run("the family of a conn", func(t *testing.T) {
		if got := ConnFamily(&store.Conn{Kind: "postgres"}); got == "" {
			t.Error("ConnFamily(postgres) is empty, want a family")
		}
		if got := ConnFamily(&store.Conn{Kind: "no-such-kind"}); got != "" {
			t.Errorf("ConnFamily(unknown) = %q, want empty", got)
		}
	})
}
