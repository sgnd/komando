package cli

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpn edit and vpn rm take one VPN or many (NAME|TARGET...), and vpn add
// and edit take --label and --protected (edit also --unset), as host and
// conn do (S-10.2). A protected VPN needs a person's yes before it is
// changed or removed; turning its protection or its --mfa off weakens a
// check, so that needs the yes too (T3s).

// vpnUnsetWords are what vpn edit --unset clears. mfa and protected are
// not among them: --mfa=false and --protected=false say it, and need a
// person's yes.
var vpnUnsetWords = []string{"user", "password-ref", "psk-ref", "id", "remote-id", "ca", "check", "notes"}

// bindInv adds --label and --protected (and --unset on edit).
func (e *vpnEditFlags) bindInv(c *cobra.Command, edit bool) {
	f := c.Flags()
	f.BoolVar(&e.protected, "protected", false, "komando asks a person before it changes or removes this VPN; an AI agent needs their yes in a window")
	if !edit {
		kvVar(f, &e.labels, "label", "", "label KEY=VALUE (repeatable)")
		return
	}
	kvVar(f, &e.labels, "label", "", "set label KEY=VALUE (an empty value removes it)")
	f.StringSliceVar(&e.unset, "unset", nil, "clear these settings: "+strings.Join(vpnUnsetWords, ","))
}

// pickVpns turns rm and edit arguments (names or selectors) into VPNs,
// each once, in order.
func pickVpns(s *store.State, args []string) ([]*store.Vpn, error) {
	var res []*store.Vpn
	seen := map[string]bool{}
	for _, a := range args {
		vs := []*store.Vpn{s.Vpns[a]}
		if vs[0] == nil {
			if !isSelector(a) {
				return nil, out.NotFound("vpn", a)
			}
			sel, err := resolveSelection(s, a)
			if err != nil {
				return nil, err
			}
			if vs = sel.Vpns; len(vs) == 0 {
				return nil, out.Errf(out.ExitNotFound, "VPN_NOT_FOUND", "run `komando list "+a+"` to see what it picks", "target %q picked no VPNs", a)
			}
		}
		for _, v := range vs {
			if !seen[v.Name] {
				seen[v.Name] = true
				res = append(res, v)
			}
		}
	}
	return res, nil
}

func vpnNames(vs []*store.Vpn) []string {
	n := make([]string, len(vs))
	for i, v := range vs {
		n[i] = v.Name
	}
	return n
}

func vpnEditCmd() *cobra.Command {
	var e vpnEditFlags
	c := &cobra.Command{
		Use:   "edit TARGET...",
		Short: "Change one or more VPNs (only the flags you pass change)",
		Long: `Changes the common settings of a VPN. To give a WireGuard or OpenVPN VPN a
new config file, add it again with --overwrite. -g and -t add a group or a
tag, as in host edit; --rm-group and --rm-tag take one away. Give several
names or a selector (@group, tag:office) to change many VPNs at once.

--protected marks a VPN komando asks a person about before it is changed
or removed. Turning that off, or turning --mfa off, needs a person's yes.`,
		Example: `  komando vpn edit office --check 10.0.0.5:22
  komando vpn edit lab --proxy-address 127.0.0.1:1081
  komando vpn edit client-x --password-ref secret:client-x-new
  komando vpn edit office --server vpn2.example.com --psk-ref secret:office-psk-2
  komando vpn edit client-x --portal gw2.client.com
  komando vpn edit office -g jakarta --rm-group old --label site=jkt
  komando vpn edit @office --protected --dry-run`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vpnEditChecks(cmd, &e); err != nil {
				return err
			}
			var res []*store.Vpn
			apply := func(s *store.State) error {
				vs, err := pickVpns(s, args)
				if err != nil {
					return err
				}
				res = nil
				olds := map[string]*store.Vpn{}
				for _, old := range vs {
					v := *old
					if err := applyVpnEdit(cmd, &e, &v); err != nil {
						return editErr(err, v.Name, len(vs) == 1)
					}
					if err := vpnOptIns(&v, cmd.Flags().Changed, e.legacyCrypto, e.allowPAP); err != nil {
						return err
					}
					if err := guardVpnSends(old, &v, ""); err != nil {
						return err
					}
					v.UpdatedAt = time.Now().UTC()
					olds[v.Name], res = old, append(res, &v)
				}
				if err := guardVpnEdit(olds, res); err != nil {
					return err
				}
				for _, v := range res {
					if !g.dryRun {
						s.Vpns[v.Name] = v
					}
				}
				return nil
			}
			return runVpnEdit(cmd, args, apply, &res)
		},
	}
	e.bind(c)
	e.bindInv(c, true)
	return c
}

// runVpnEdit runs apply (in a dry run on the state as it is) and prints
// what changed: one VPN as before ({"vpn": ...}), several as a list.
func runVpnEdit(cmd *cobra.Command, args []string, apply func(*store.State) error, res *[]*store.Vpn) error {
	if g.dryRun {
		st, err := loadState()
		if err != nil {
			return err
		}
		if err := apply(st); err != nil {
			return err
		}
		if len(*res) == 1 && len(args) == 1 && !isSelector(args[0]) {
			out.P.Print("vpn.edit", textAs{map[string]any{"would_change": (*res)[0]}, vpnChangeText{verb: "would change", v: (*res)[0]}}, nil)
			return nil
		}
		out.P.Print("vpn.edit", textAs{map[string]any{"would_change": *res}, vpnManyText{"would change", *res}}, nil)
		return nil
	}
	if err := store.Update(apply); err != nil {
		return err
	}
	audit(nil, "vpn.edit", vpnNames(*res), "", true, map[string]any{"flags": changedFlags(cmd)})
	if len(*res) == 1 && len(args) == 1 && !isSelector(args[0]) {
		v := (*res)[0]
		data := map[string]any{"vpn": v}
		w := refWarnings(v.KeyRef, v.PSKRef)
		if len(w) > 0 {
			data["warnings"] = w
		}
		out.P.Print("vpn.edit", textAs{data, vpnChangeText{verb: "changed", v: v, warnings: w}}, nil)
		return nil
	}
	out.P.Print("vpn.edit", textAs{map[string]any{"vpns": *res, "changed": vpnNames(*res)}, vpnManyText{"changed", *res}}, nil)
	return nil
}

// vpnManyText is vpn edit of several VPNs, for a person.
type vpnManyText struct {
	verb string
	vs   []*store.Vpn
}

func (t vpnManyText) Text() string {
	s := t.verb + ": " + dash(strings.Join(vpnNames(t.vs), ", "))
	if strings.HasPrefix(t.verb, "would ") {
		s += " (dry run)"
	}
	return s
}

// vpnEditChecks are vpn edit's checks of its flags alone.
func vpnEditChecks(cmd *cobra.Command, e *vpnEditFlags) error {
	f := cmd.Flags()
	if len(changedFlags(cmd)) == 0 {
		return out.Usage("nothing to change: give at least one of --check, --proxy-address, --service, --server, --portal, --user, --password-ref, --psk-ref, --id, --remote-id, --ca, --mfa, --legacy-crypto, --allow-pap, --notes, --label, --protected, --unset, --add-group, --rm-group, --add-tag, --rm-tag")
	}
	for _, u := range e.unset {
		switch {
		case u == "mfa" || u == "protected":
			return out.Errf(out.ExitUsage, "USAGE", "use --"+u+"=false: turning it off needs a person's yes",
				"--unset does not take %s", u)
		case !slices.Contains(vpnUnsetWords, u):
			return out.Errf(out.ExitUsage, "USAGE", "--unset takes: "+strings.Join(vpnUnsetWords, ", "), "cannot unset %q", u)
		}
	}
	fields := map[string]string{}
	for _, w := range vpnUnsetWords {
		fields[w] = w
	}
	if err := editConflicts(f, e.unset, fields, [][2][]string{{e.addGroups, e.rmGroups}, {e.addTags, e.rmTags}}); err != nil {
		return err
	}
	if f.Changed("portal") && (e.portal == "" || strings.HasPrefix(e.portal, "-")) {
		return out.Usage("--portal must be a server name or URL")
	}
	if e.check != "" {
		if _, _, err := net.SplitHostPort(e.check); err != nil {
			return out.Usage("--check must be host:port")
		}
	}
	for flag, ref := range map[string]string{"password-ref": e.passwordRef, "psk-ref": e.pskRef} {
		if ref != "" && !vault.ValidRef(ref) {
			return out.Usage("--%s %q is not a reference: %s", flag, ref, vault.RefHelp())
		}
	}
	_, err := parseKV(e.labels)
	return err
}

// vpnKindFlags are the flags only some kinds of VPN use.
var vpnKindFlags = map[string][]string{"proxy-address": {"socks", "proxy"}, "service": {"system"},
	"server": {"l2tp", "ipsec", "ikev2"}, "psk-ref": {"l2tp", "ipsec", "ikev2"}, "id": {"ipsec", "ikev2"}, "remote-id": {"ikev2"},
	"portal": {"globalprotect", "fortinet", "anyconnect", "pulse", "f5"}, "ca": {"ikev2"}}

// applyVpnEdit changes v (a copy) as the flags say.
func applyVpnEdit(cmd *cobra.Command, e *vpnEditFlags, v *store.Vpn) error {
	f := cmd.Flags()
	for flag, kinds := range vpnKindFlags {
		if (flagChanged(cmd, flag) || flag != "proxy-address" && slices.Contains(e.unset, flag)) && !oneOf(v.Kind, kinds...) {
			return out.Usage("--%s is not used by %s VPNs", flag, v.Kind)
		}
	}
	if v.Kind == "wireguard" && (f.Changed("password-ref") || f.Changed("user") || slices.Contains(e.unset, "password-ref") || slices.Contains(e.unset, "user")) {
		return out.Usage("WireGuard keys come from its config: add it again with --config and --overwrite")
	}
	if flagChanged(cmd, "proxy-address") {
		a, err := vpnAddress(v.Kind, e.address)
		if err != nil {
			return err
		}
		v.Address = a
	}
	if err := applyVpnFields(f, e, v); err != nil {
		return err
	}
	for _, u := range e.unset {
		*map[string]*string{"user": &v.User, "password-ref": &v.KeyRef, "psk-ref": &v.PSKRef, "id": &v.LocalID,
			"remote-id": &v.RemoteID, "ca": &v.CA, "check": &v.Check, "notes": &v.Notes}[u] = ""
	}
	switch {
	case v.Check == "" && oneOf(v.Kind, "system", "openvpn"):
		return out.Usage("%s VPNs need --check", v.Kind)
	case v.PSKRef == "" && oneOf(v.Kind, "l2tp", "ipsec"):
		return out.Usage("%s VPNs need --psk-ref", v.Kind)
	}
	v.Groups = dedupe(append(removeFold(v.Groups, e.rmGroups), e.addGroups...))
	v.Tags = dedupe(append(removeFold(v.Tags, e.rmTags), e.addTags...))
	return applyKV(&v.Labels, e.labels)
}

// applyVpnFields sets the plain settings the flags give.
func applyVpnFields(f *pflag.FlagSet, e *vpnEditFlags, v *store.Vpn) error {
	if f.Changed("server") {
		if e.server == "" || strings.HasPrefix(e.server, "-") || strings.Contains(e.server, "/") {
			return out.Usage("--server must be a host name or address (host or host:port)")
		}
	}
	if f.Changed("ca") {
		ca, err := readVpnCA(e.ca)
		if err != nil {
			return err
		}
		v.CA = ca
	}
	for flag, p := range map[string][2]*string{"check": {&v.Check, &e.check}, "service": {&v.Service, &e.service}, "server": {&v.Server, &e.server},
		"portal": {&v.Portal, &e.portal}, "psk-ref": {&v.PSKRef, &e.pskRef}, "id": {&v.LocalID, &e.localID}, "remote-id": {&v.RemoteID, &e.remoteID},
		"user": {&v.User, &e.user}, "password-ref": {&v.KeyRef, &e.passwordRef}, "notes": {&v.Notes, &e.notes}} {
		if f.Changed(flag) {
			*p[0] = *p[1]
		}
	}
	if f.Changed("mfa") {
		v.MFA = e.mfa
	}
	if f.Changed("protected") {
		v.Protected = e.protected
	}
	return nil
}

// guardVpnEdit asks once about what the edit weakens or touches: turning
// protection or --mfa off (a safety setting), and any other change to a
// protected VPN (--yes, as for a protected server's login).
func guardVpnEdit(olds map[string]*store.Vpn, now []*store.Vpn) error {
	var prot []string
	for _, v := range now {
		o := olds[v.Name]
		if o.Protected && !v.Protected {
			if err := guardSafety("turning off the protection of VPN " + v.Name); err != nil {
				return err
			}
		}
		if o.MFA && !v.MFA {
			if err := guardSafety("turning off --mfa of VPN " + v.Name + " (komando could then connect it without a person)"); err != nil {
				return err
			}
		}
		if o.Protected && v.Protected && vpnChanged(o, v) {
			prot = append(prot, v.Name)
		}
	}
	return guardProtection("vpn", "changing", prot)
}

// vpnChanged: anything but the time it was changed differs.
func vpnChanged(a, b *store.Vpn) bool {
	x, y := *a, *b
	x.UpdatedAt, y.UpdatedAt = time.Time{}, time.Time{}
	return fmt.Sprintf("%+v", x) != fmt.Sprintf("%+v", y)
}

func vpnRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm TARGET...",
		Short: "Remove VPNs (from komando only)",
		Example: `  komando vpn rm old-office
  komando vpn rm @lab --dry-run       # what a selector would remove`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// all or nothing, like host rm: a VPN in use stops the whole call
			var names []string
			check := func(s *store.State) error {
				vs, err := pickVpns(s, args)
				if err != nil {
					return err
				}
				names = vpnNames(vs)
				var prot []string
				for _, v := range vs {
					if users := vpnUsers(s, v.Name); len(users) > 0 {
						return out.Errf(out.ExitConflict, "VPN_IN_USE", "change their --via first: `komando host edit TARGET --via OTHER`", "VPN %s is on the --via path of %s", v.Name, strings.Join(users, ", "))
					}
					if v.Protected {
						prot = append(prot, v.Name)
					}
				}
				return guardProtection("vpn", "removing", prot)
			}
			// one name: the name itself; several: the list
			one := func() any {
				if len(names) == 1 && len(args) == 1 && !isSelector(args[0]) {
					return names[0]
				}
				return names
			}
			if g.dryRun { // the same checks as the real removal
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := check(st); err != nil {
					return err
				}
				out.P.Print("vpn.rm", map[string]any{"would_remove": one()}, nil)
				return nil
			}
			unused, warnings, err := vpnRemove(check, &names)
			if err != nil {
				return err
			}
			audit(nil, "vpn.rm", names, "", true, nil)
			res := map[string]any{"removed": one()} // one VPN stays a string, so scripts that read it keep working
			if len(unused) > 0 {
				res["secrets_unused"] = unused
			}
			if len(warnings) > 0 {
				res["warnings"] = warnings
			}
			out.P.Print("vpn.rm", textAs{res, rmResult{Removed: names, SecretsUnused: unused}}, nil)
			return nil
		},
	}
}

// vpnRemove takes the VPNs check picks out of the state (disconnecting
// any that is up) and says which of their vault secrets nothing uses now.
func vpnRemove(check func(*store.State) error, names *[]string) (unused, warnings []string, err error) {
	var gone []*store.Vpn
	err = store.Update(func(s *store.State) error {
		if err := check(s); err != nil {
			return err
		}
		var refs []string
		for _, name := range *names {
			v := s.Vpns[name]
			refs = append(refs, v.KeyRef, v.PSKRef, v.ConfigRef)
			gone = append(gone, v)
			if sess := s.Sessions[name]; sess != nil {
				if err := netx.StopSession(sess); err != nil {
					return out.Errf(out.ExitError, "VPN_STOP_FAILED", "disconnect it first with `komando vpn down "+name+"`", "%v", err)
				}
				delete(s.Sessions, name)
			}
			delete(s.Vpns, name)
		}
		unused = unusedSecrets(s, refs)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// a Tailscale node's keys go with it: a VPN added later under the same
	// name must not join as the old node
	for _, v := range gone {
		if v.Kind == "tailscale" {
			if ferr := netx.ForgetTailscale(v); ferr != nil {
				warnings = append(warnings, fmt.Sprintf("the Tailscale node state of %s could not be removed: %v", v.Name, ferr))
			}
		}
	}
	return unused, warnings, nil
}

// vpnUnusedFlags refuses a vpn add flag the kind does not use.
func vpnUnusedFlags(kind string, used map[string]bool, given map[string]string) error {
	for flag, val := range given {
		if val != "" && !used[flag] {
			return out.Usage("--%s is not used by %s VPNs", flag, kind)
		}
	}
	return nil
}

// vpnAddFlagChecks checks vpn add's --check and references, and sets its
// labels on v.
func vpnAddFlagChecks(v *store.Vpn, pskRef string, labels []string) error {
	if v.Check != "" {
		if _, _, err := net.SplitHostPort(v.Check); err != nil {
			return out.Usage("--check must be host:port")
		}
	}
	for _, r := range []string{v.KeyRef, pskRef} {
		if r != "" && !vault.ValidRef(r) {
			return out.Usage("%q is not a reference: %s", r, vault.RefHelp())
		}
	}
	return applyKV(&v.Labels, labels)
}

// kvPairs is a map as KEY=VALUE words, sorted.
func kvPairs(m map[string]string) []string {
	var s []string
	for k, v := range m {
		s = append(s, k+"="+v)
	}
	slices.Sort(s)
	return s
}
