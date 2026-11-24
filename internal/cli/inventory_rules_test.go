package cli

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
			if err := validName("host", n); err != nil {
				t.Errorf("validName(host, %q) = %v, want nil", n, err)
			}
		}
		for _, n := range []string{"", "-x", "bad name", "a/b", "x:y"} {
			if validName("host", n) == nil {
				t.Errorf("validName(host, %q) = nil, want an error", n)
			}
		}
		for _, kind := range []string{"host", "conn", "vpn"} {
			if validName(kind, "ALL") == nil {
				t.Errorf("validName(%s, ALL) = nil: all means everything as a target", kind)
			}
		}
		if err := validName("secret", "all"); err != nil {
			t.Errorf("validName(secret, all) = %v, want nil: only targets reserve all", err)
		}
	})
	t.Run("a login name", func(t *testing.T) {
		for _, u := range []string{"deploy", "_svc", "a.b-c", "user@dom", "ci$"} {
			if err := validUser(u); err != nil {
				t.Errorf("validUser(%q) = %v, want nil", u, err)
			}
		}
		for _, u := range []string{"", "a b", "-x", "a;b"} {
			if validUser(u) == nil {
				t.Errorf("validUser(%q) = nil, want an error", u)
			}
		}
	})
	t.Run("a port", func(t *testing.T) {
		for _, p := range []int{0, 1, 22, 65535} {
			if err := validPort(p); err != nil {
				t.Errorf("validPort(%d) = %v, want nil", p, err)
			}
		}
		for _, p := range []int{-1, 65536} {
			if validPort(p) == nil {
				t.Errorf("validPort(%d) = nil, want an error", p)
			}
		}
	})
	t.Run("a label", func(t *testing.T) {
		if err := validLabelName("group", "prod-eu"); err != nil {
			t.Errorf("validLabelName(group, prod-eu) = %v", err)
		}
		for _, n := range []string{"", "bad name", "a,b"} {
			if validLabelName("tag", n) == nil {
				t.Errorf("validLabelName(tag, %q) = nil, want an error", n)
			}
		}
		if err := checkLabels([]string{"web"}, []string{"prod"}, map[string]string{"env": "eu"}); err != nil {
			t.Errorf("checkLabels(valid) = %v", err)
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
			if checkLabels(args.g, args.t, args.l) == nil {
				t.Errorf("checkLabels with %s = nil, want an error", name)
			}
		}
		if !hasControl("a\x01b") || !hasControl("a\x7fb") || hasControl("ab") {
			t.Errorf("hasControl is wrong for a control character, DEL and plain text")
		}
	})
	t.Run("a via path", func(t *testing.T) {
		if got, want := viaChain(" vpn1, bastion ,,web"), []string{"vpn1", "bastion", "web"}; !slices.Equal(got, want) {
			t.Errorf("viaChain = %v, want %v", got, want)
		}
		if got := viaChain(""); len(got) != 0 {
			t.Errorf("viaChain(empty) = %v, want nothing", got)
		}
		st := &store.State{Hosts: map[string]*store.Host{
			"a": {Name: "a", Via: "b,c"}, "b": {Name: "b", Via: "a"}, "c": {Name: "c"},
		}}
		if got, want := waySteps(st, "a", map[string]bool{}), []string{"a", "b", "c"}; !slices.Equal(got, want) {
			t.Errorf("waySteps(a) = %v, want %v (a cycle is cut, each name once)", got, want)
		}
	})
	t.Run("the family of a conn", func(t *testing.T) {
		if got := connFamily(&store.Conn{Kind: "postgres"}); got == "" {
			t.Error("connFamily(postgres) is empty, want a family")
		}
		if got := connFamily(&store.Conn{Kind: "no-such-kind"}); got != "" {
			t.Errorf("connFamily(unknown) = %q, want empty", got)
		}
	})
}
