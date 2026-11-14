package cli

import (
	"cmp"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
)

// schemaAddKinds is the add_kinds list of `komando schema PATH...`.
func schemaAddKinds[T any](t *testing.T, path ...string) (kinds []T, flags []string) {
	t.Helper()
	invHome(t)
	d := mustRun(t, append([]string{"schema"}, path...)...)
	cmds, _ := d["commands"].([]any)
	if len(cmds) != 1 {
		t.Fatalf("schema %v: %d commands", path, len(cmds))
	}
	c := cmds[0].(map[string]any)
	for _, f := range c["flags"].([]any) {
		flags = append(flags, f.(map[string]any)["name"].(string))
	}
	b, _ := json.Marshal(c["add_kinds"])
	if err := json.Unmarshal(b, &kinds); err != nil || len(kinds) == 0 {
		t.Fatalf("schema %v: no add_kinds (%v): %s", path, err, b)
	}
	return kinds, flags
}

// kindFlags are the flags a kind lists, all together.
func kindFlags(required []string, oneOf [][]string, optional []string) []string {
	res := slices.Clone(required)
	for _, g := range oneOf {
		res = append(res, g...)
	}
	return append(res, optional...)
}

// `komando schema vpn add` lists every kind vpn add accepts, each flag it
// names is one of vpn add's, and together they name every flag vpn add
// has: an app builds its VPN forms from it.
func TestSchemaVpnAddKinds(t *testing.T) {
	kinds, flags := schemaAddKinds[vpnKindSchema](t, "vpn", "add")
	var ids []string
	all := map[string]bool{}
	families := []string{"portal", "config_file", "server_psk", "auth_key", "system", "proxy"}
	for _, k := range kinds {
		ids = append(ids, k.ID)
		if k.DisplayName == "" || k.Description == "" || !slices.Contains(families, k.Family) {
			t.Errorf("%s: name %q, description %q, family %q", k.ID, k.DisplayName, k.Description, k.Family)
		}
		for _, f := range kindFlags(k.Required, k.OneOf, k.Optional) {
			if !slices.Contains(flags, f) {
				t.Errorf("%s lists --%s, which vpn add does not have", k.ID, f)
			}
			if all[k.ID+" "+f] {
				t.Errorf("%s lists --%s twice", k.ID, f)
			}
			all[k.ID+" "+f], all[f] = true, true
		}
		for f := range k.FlagNotes {
			if !all[k.ID+" "+f] {
				t.Errorf("%s has a note for --%s, which it does not list", k.ID, f)
			}
		}
		if want := k.ID == "globalprotect" || k.ID == "tailscale"; k.OpensBrowser != want || (k.BrowserNote != "") != want {
			t.Errorf("%s: opens_browser %v %q", k.ID, k.OpensBrowser, k.BrowserNote)
		}
		for _, a := range k.Aliases {
			if vpnKindWord(strings.ToUpper(a)) != k.ID {
				t.Errorf("alias %s is not %s", a, k.ID)
			}
		}
	}
	sort.Strings(ids)
	if !slices.Equal(ids, netx.KindNames()) {
		t.Errorf("add_kinds %v, vpn add accepts %v", ids, netx.KindNames())
	}
	for _, f := range flags {
		if !all[f] && f != "help" {
			t.Errorf("no kind lists --%s", f)
		}
	}
}

// vpnAddFlags are vpn add's flags.
func vpnAddFlags(t *testing.T) *pflag.FlagSet {
	t.Helper()
	c, _, err := newRoot(tcl).Find([]string{"vpn", "add"})
	if err != nil {
		t.Fatal(err)
	}
	return c.Flags()
}

// vpn add does what add_kinds says: with what a kind needs it adds the
// VPN, and with all it lists too, keeping each value; without a flag it needs, or with a flag of
// another kind, it stops.
func TestVpnAddKindsMatchTheCommand(t *testing.T) {
	invHome(t)
	wg, ovpn := vpnSecretFiles(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := vpnAddFlags(t)
	// each value differs, so the VPN shows where each went
	value := map[string]string{"check": "10.0.0.1:22", "portal": "portal.example.com", "server": "server.example.com", "user": "alice",
		"password-ref": "secret:office-pass", "psk-ref": "secret:office-psk", "id": "staff-group", "remote-id": "remote.example.com", "ca": ca,
		"service": "Corp VPN", "proxy-address": "127.0.0.1:1080", "label": "site=jakarta", "group": "lab", "tag": "prodtag", "notes": "test-notes"}
	// kept is how a value shows in the VPN vpn add would save
	kept := map[string]string{"ca": "MIIB", "label": `"site":"jakarta"`, "mfa": `"mfa":true`, "protected": `"protected":true`}
	arg := func(kind, flag string) []string {
		switch {
		case flag == "config" && kind == "wireguard":
			return []string{"--config", wg("1")}
		case flag == "config":
			return []string{"--config", ovpn("1")}
		case fs.Lookup(flag).Value.Type() == "bool" && (flag == "legacy-crypto" || flag == "allow-pap"):
			return []string{"--" + flag + "=false"} // true needs a person's yes
		case fs.Lookup(flag).Value.Type() == "bool":
			return []string{"--" + flag}
		}
		return []string{"--" + flag, value[flag]}
	}
	run := func(kind string, flags []string) []string {
		args := []string{"--dry-run", "vpn", "add", "office", kind}
		for _, f := range flags {
			args = append(args, arg(kind, f)...)
		}
		return args
	}
	asked := []string{"ask-password", "ask-psk"} // a person types those: not run here
	perKind := map[string]bool{}
	for _, s := range vpnKindSpecs {
		for _, f := range kindFlags(s.need, s.oneOf, s.takes) {
			perKind[f] = !slices.Contains(vpnEveryKind, f)
		}
	}
	for _, k := range vpnKindSchemas() {
		var groups []string // one flag of each one_of group
		for _, g := range k.OneOf {
			groups = append(groups, g[0])
		}
		var opt []string
		for _, f := range k.Optional {
			if !slices.Contains(asked, f) {
				opt = append(opt, f)
			}
		}
		least := append(slices.Clone(k.Required), groups...)
		if _, e := cliRun(t, run(k.ID, least)...); e != nil {
			t.Errorf("%s with only what it needs: %s: %s", k.ID, e.Code, e.Message)
		}
		full := append(slices.Clone(least), opt...)
		d, e := cliRun(t, run(k.ID, full)...)
		if e != nil {
			t.Errorf("%s with every flag it lists: %s: %s", k.ID, e.Code, e.Message)
			continue
		}
		saved, _ := json.Marshal(d["would_add"])
		for _, f := range full {
			want := cmp.Or(kept[f], value[f])
			if fs.Lookup(f).Value.Type() == "bool" && kept[f] == "" || f == "config" {
				continue // the overwrite and opt-in switches; a config file goes to the vault
			}
			if !strings.Contains(string(saved), want) {
				t.Errorf("%s: --%s %s is not kept: %s", k.ID, f, want, saved)
			}
		}
		for _, f := range k.Required {
			if _, e := cliRun(t, run(k.ID, slices.DeleteFunc(slices.Clone(full), func(x string) bool { return x == f }))...); e == nil || e.Code != "USAGE" {
				t.Errorf("%s without --%s: %+v", k.ID, f, e)
			}
		}
		for _, g := range k.OneOf {
			if _, e := cliRun(t, run(k.ID, slices.DeleteFunc(slices.Clone(full), func(x string) bool { return slices.Contains(g, x) }))...); e == nil || e.Code != "USAGE" {
				t.Errorf("%s without any of %v: %+v", k.ID, g, e)
			}
		}
		for f, only := range perKind {
			if !only || slices.Contains(kindFlags(k.Required, k.OneOf, k.Optional), f) {
				continue
			}
			if _, e := cliRun(t, append(run(k.ID, full), arg(k.ID, f)...)...); e == nil || e.Code != "USAGE" {
				t.Errorf("%s with --%s, which it does not list: %+v", k.ID, f, e)
			}
		}
	}
}

// vpn add's help table comes from the same kinds: every kind and every
// flag a kind takes is in it, and no line is wider than the help.
func TestVpnAddHelpTable(t *testing.T) {
	var c *cobra.Command
	c, _, _ = newRoot(tcl).Find([]string{"vpn", "add"})
	_, table, ok := strings.Cut(c.Long, "Which flags go with which VPN kind:")
	if !ok {
		t.Fatalf("no table in vpn add's help:\n%s", c.Long)
	}
	for _, s := range vpnKindSpecs {
		if !strings.Contains(table, s.kind) {
			t.Errorf("%s is not in the table", s.kind)
		}
		for _, f := range kindFlags(s.need, s.oneOf, s.takes) {
			if !strings.Contains(table, "--"+f) {
				t.Errorf("--%s is not in the table", f)
			}
		}
	}
	for _, l := range strings.Split(table, "\n") {
		if len([]rune(l)) > helpWidth {
			t.Errorf("a line of %d columns: %s", len([]rune(l)), l)
		}
	}
}

// `komando schema conn add` lists every conn kind with its URL schemes
// and the flags conn add takes for it; db add, cache add and the other
// family adds list their own kinds only.
func TestSchemaConnAddKinds(t *testing.T) {
	kinds, flags := schemaAddKinds[connKindSchema](t, "conn", "add")
	var ids []string
	for _, k := range kinds {
		ids = append(ids, k.ID)
		d, ok := driver.Lookup(k.ID)
		if !ok || k.Family != d.Family || !slices.Equal(k.URLSchemes, d.Schemes) || k.DisplayName == "" {
			t.Errorf("%s: %+v", k.ID, k)
		}
		if tg, err := driver.Parse(k.URLExample); err != nil || tg.Kind.Name != k.ID {
			t.Errorf("%s: url_example %q is not a %s URL: %v", k.ID, k.URLExample, k.ID, err)
		}
		for _, f := range kindFlags(k.Required, k.OneOf, k.Optional) {
			if !slices.Contains(flags, f) {
				t.Errorf("%s lists --%s, which conn add does not have", k.ID, f)
			}
		}
		if slices.Contains(k.Optional, "via") == k.File {
			t.Errorf("%s: a file kind takes no --via, others do: %v", k.ID, k.Optional)
		}
	}
	var want []string
	for _, k := range driver.Kinds() {
		want = append(want, k.Name)
	}
	if !slices.Equal(ids, want) {
		t.Errorf("add_kinds %v, conn add accepts %v", ids, want)
	}
	wantCode(t, "USAGE", "conn", "add", "local", "sqlite:///var/lib/app.db", "--via", "web1")

	for family := range connAddKinds {
		kinds, _ := schemaAddKinds[connKindSchema](t, family, "add")
		for _, k := range kinds {
			if k.Family != family {
				t.Errorf("%s add lists %s, a %s kind", family, k.ID, k.Family)
			}
			if need := k.ID == "k8s"; slices.Contains(k.Required, "password-ref") != need || slices.Contains(k.Optional, "ask-password") == need {
				t.Errorf("%s add, %s: required %v optional %v", family, k.ID, k.Required, k.Optional)
			}
		}
	}
	wantCode(t, "USAGE", "cluster", "add", "prod-k8s", "k8s://api.cluster.example:6443")
}
