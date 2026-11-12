package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// vpnDialCheck is how long `vpn status` waits for an address to answer.
const vpnDialCheck = 1500 * time.Millisecond

// vpnReachable reports, for the kinds komando does not run itself (socks
// and system), whether the VPN answers right now, and how that was seen.
func vpnReachable(v *store.Vpn) (up bool, detail string) {
	addr, what := "", ""
	switch v.Kind {
	case "socks":
		addr, what = v.Address, "SOCKS proxy "+v.Address
	case "proxy":
		if u, err := netx.ProxyURL(v.Address); err == nil {
			addr = u.Host
			if u.Port() == "" {
				addr += map[bool]string{true: ":443", false: ":80"}[u.Scheme == "https"]
			}
		}
		what = "HTTP proxy " + v.Address
	case "system":
		if v.Check == "" {
			return false, "no --check address to test"
		}
		addr, what = v.Check, v.Check
	default:
		return false, ""
	}
	c, err := net.DialTimeout("tcp", addr, vpnDialCheck)
	if err != nil {
		return false, what + " does not answer"
	}
	c.Close()
	return true, what + " answers"
}

type vpnStatusData struct {
	Vpns []vpnStatusRow `json:"vpns"`
}

func (d vpnStatusData) Text() string {
	if len(d.Vpns) == 0 {
		return "no VPNs yet: komando vpn add NAME KIND (kinds in `komando vpn --help`)\n"
	}
	rows := [][]string{}
	for _, r := range d.Vpns {
		up := "no"
		if r.Up {
			up = "yes"
		}
		since := ""
		if !r.Since.IsZero() {
			since = humanAge(time.Since(r.Since))
		}
		rows = append(rows, []string{r.Name, r.Kind, up, since, usedByText(r.UsedBy), r.Detail})
	}
	return textTable([]string{"name", "kind", "up", "since", "used by", "detail"}, rows)
}

// vpnStatusRows builds the status of every VPN; the address checks run
// at the same time, so the command stays quick.
func vpnStatusRows(st *store.State) []vpnStatusRow {
	vpns := st.SortedVpns()
	rows := make([]vpnStatusRow, len(vpns))
	var wg sync.WaitGroup
	for i, v := range vpns {
		r := vpnStatusRow{Name: v.Name, Kind: v.Kind, MFA: v.MFA, UsedBy: vpnUsers(st, v.Name)}
		if s := st.Sessions[v.Name]; s != nil && netx.SessionAlive(s) {
			r.Up, r.Since, r.LastUsed, r.Socks = true, s.StartedAt, s.LastUsed, s.Socks
			r.Detail = "session running"
		} else if v.Kind == "socks" || v.Kind == "proxy" || v.Kind == "system" {
			wg.Add(1)
			go func(i int, v *store.Vpn) {
				defer wg.Done()
				rows[i].Up, rows[i].Detail = vpnReachable(v)
			}(i, v)
		} else if v.Kind == "wireguard" {
			r.Detail = "connects for each command"
		} else {
			r.Detail = "not connected"
			r.LastEnd, r.LastLog = lastSessionEnd(v.Name, oneOf(v.Kind, "l2tp", "ipsec", "ikev2"))
		}
		rows[i] = r
	}
	wg.Wait()
	return rows
}

// lastSessionEnd is why the VPN's last background session ended or did
// not start, as its log says ("ENDED ..." or "ERROR ..."), cleaned for output.
// With tail, it also returns the log's last lines (only for kinds whose
// logs komando writes itself and keeps free of secrets).
func lastSessionEnd(name string, tail bool) (string, []string) {
	dir, err := vpnDir()
	if err != nil {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".log"))
	if err != nil {
		return "", nil
	}
	last := ""
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if i := strings.Index(line, "ENDED "); i >= 0 && (i == 0 || line[i-1] == ' ') {
			last = line[i+len("ENDED "):]
			if i > 0 { // the time it ended
				last = strings.TrimSpace(line[:i]) + ": " + last
			}
		} else if strings.HasPrefix(line, "ERROR ") {
			last = strings.TrimPrefix(line, "ERROR ")
		}
		if len(line) > 300 {
			line = line[:300]
		}
		lines = append(lines, cleanText(line))
	}
	if len(last) > 300 {
		last = last[:300]
	}
	if !tail || last == "" {
		lines = nil
	} else if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return cleanText(last), lines
}

// refWarnings checks, at add time, that the secret references a VPN uses
// can be read here; the cheap kinds only (external managers may prompt).
func refWarnings(refs ...string) []string {
	var w []string
	for _, ref := range refs {
		if ref == "" || !(strings.HasPrefix(ref, "secret:") || strings.HasPrefix(ref, "env:") || strings.HasPrefix(ref, "file:")) {
			continue
		}
		if _, err := vault.Resolve(ref); err != nil {
			w = append(w, ref+" cannot be read yet ("+err.Error()+"); "+netx.SecretHint(ref))
		}
	}
	return w
}

// socksTunnel finds the `komando tunnel` that serves a SOCKS address.
func socksTunnel(st *store.State, addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	for _, t := range st.Tunnels {
		if t.Kind == "dynamic" && (t.Spec == addr || t.Spec == port || strings.HasSuffix(t.Spec, ":"+port)) {
			return t.ID
		}
	}
	return ""
}

func vpnEditCmd() *cobra.Command {
	var e vpnEditFlags
	c := &cobra.Command{
		Use:   "edit NAME",
		Short: "Change a VPN's check address, server, portal, proxy, login or notes",
		Long: `Changes the common settings of a VPN. To give a WireGuard or OpenVPN VPN a
new config file, add it again with --overwrite. -g and -t add a group or a
tag, as in host edit; --rm-group and --rm-tag take one away.`,
		Example: `  komando vpn edit office --check 10.0.0.5:22
  komando vpn edit lab --proxy-address 127.0.0.1:1081
  komando vpn edit client-x --password-ref secret:client-x-new
  komando vpn edit kantor --server vpn2.kantor.id --psk-ref secret:kantor-psk-2
  komando vpn edit client-x --portal gw2.client.com
  komando vpn edit office -g jakarta --rm-group old`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			if len(changedFlags(cmd)) == 0 {
				return out.Usage("nothing to change: give at least one of --check, --proxy-address, --service, --server, --portal, --user, --password-ref, --psk-ref, --id, --remote-id, --ca, --mfa, --legacy-crypto, --allow-pap, --notes, --add-group, --rm-group, --add-tag, --rm-tag")
			}
			if err := editConflicts(f, nil, nil, [][2][]string{{e.addGroups, e.rmGroups}, {e.addTags, e.rmTags}}); err != nil {
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
			if e.passwordRef != "" && !vault.ValidRef(e.passwordRef) {
				return out.Usage("invalid --password-ref %q: %s", e.passwordRef, vault.RefHelp())
			}
			if e.pskRef != "" && !vault.ValidRef(e.pskRef) {
				return out.Usage("invalid --psk-ref %q: %s", e.pskRef, vault.RefHelp())
			}
			var res *store.Vpn
			apply := func(s *store.State) error {
				cur, ok := s.Vpns[args[0]]
				if !ok {
					return out.NotFound("vpn", args[0])
				}
				v := *cur
				for flag, kinds := range map[string][]string{"proxy-address": {"socks", "proxy"}, "service": {"system"},
					"server": {"l2tp", "ipsec", "ikev2"}, "psk-ref": {"l2tp", "ipsec", "ikev2"}, "id": {"ipsec", "ikev2"}, "remote-id": {"ikev2"},
					"portal": {"globalprotect", "fortinet", "anyconnect", "pulse", "f5"}, "ca": {"ikev2"}} {
					if flagChanged(cmd, flag) && !oneOf(v.Kind, kinds...) {
						return out.Usage("--%s is not used by %s VPNs", flag, v.Kind)
					}
				}
				if v.Kind == "wireguard" && (f.Changed("password-ref") || f.Changed("user")) {
					return out.Usage("WireGuard keys come from its config: add it again with --config and --overwrite")
				}
				if flagChanged(cmd, "proxy-address") {
					var err error
					if v.Address, err = vpnAddress(v.Kind, e.address); err != nil {
						return err
					}
				}
				if f.Changed("check") {
					if e.check == "" && oneOf(v.Kind, "system", "openvpn") {
						return out.Usage("%s VPNs need --check", v.Kind)
					}
					v.Check = e.check
				}
				if f.Changed("service") {
					v.Service = e.service
				}
				if f.Changed("server") {
					if e.server == "" || strings.HasPrefix(e.server, "-") || strings.Contains(e.server, "/") {
						return out.Usage("--server must be a host name or address (host or host:port)")
					}
					v.Server = e.server
				}
				if f.Changed("portal") {
					v.Portal = e.portal
				}
				if f.Changed("ca") {
					var err error
					if v.CA, err = readVpnCA(e.ca); err != nil {
						return err
					}
				}
				if f.Changed("psk-ref") {
					if e.pskRef == "" && v.Kind != "ikev2" {
						return out.Usage("%s VPNs need --psk-ref", v.Kind)
					}
					v.PSKRef = e.pskRef
				}
				if f.Changed("id") {
					v.LocalID = e.localID
				}
				if f.Changed("remote-id") {
					v.RemoteID = e.remoteID
				}
				if f.Changed("user") {
					v.User = e.user
				}
				if f.Changed("password-ref") {
					v.KeyRef = e.passwordRef
				}
				if f.Changed("mfa") {
					v.MFA = e.mfa
				}
				if f.Changed("notes") {
					v.Notes = e.notes
				}
				v.Groups = dedupe(append(removeFold(v.Groups, e.rmGroups), e.addGroups...))
				v.Tags = dedupe(append(removeFold(v.Tags, e.rmTags), e.addTags...))
				v.UpdatedAt = time.Now().UTC()
				res = &v
				if !g.dryRun {
					s.Vpns[v.Name] = &v
				}
				return nil
			}
			apply = withVpnGuards(args[0], f.Changed, &res, e.legacyCrypto, e.allowPAP, apply)
			if g.dryRun {
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := apply(st); err != nil {
					return err
				}
				out.P.Print("vpn.edit", textAs{map[string]any{"would_change": res}, vpnChangeText{verb: "would change", v: res}}, nil)
				return nil
			}
			if err := store.Update(apply); err != nil {
				return err
			}
			audit(nil, "vpn.edit", []string{args[0]}, "", true, nil)
			data := map[string]any{"vpn": res}
			w := refWarnings(res.KeyRef, res.PSKRef)
			if len(w) > 0 {
				data["warnings"] = w
			}
			out.P.Print("vpn.edit", textAs{data, vpnChangeText{verb: "changed", v: res, warnings: w}}, nil)
			return nil
		},
	}
	e.bind(c)
	return c
}

// vpnEditFlags are vpn edit's flags.
type vpnEditFlags struct {
	check, address, service, user, passwordRef, notes, server, pskRef, localID, remoteID, portal, ca string
	addGroups, rmGroups, addTags, rmTags                                                             []string
	mfa, legacyCrypto, allowPAP                                                                      bool
}

func (e *vpnEditFlags) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&e.check, "check", "", "host:port reachable only through this VPN")
	f.StringVar(&e.address, "proxy-address", "", "SOCKS: host:port of the proxy; proxy: host:port or http(s)://host:port")
	withRetiredAddress(c)
	f.StringVar(&e.service, "service", "", "System VPN: its name in your computer's settings")
	f.StringVar(&e.server, "server", "", "L2TP, IPsec, IKEv2: the VPN server")
	f.StringVar(&e.portal, "portal", "", "GlobalProtect, Fortinet, AnyConnect, Pulse, F5: the VPN server or portal")
	f.StringVar(&e.ca, "ca", "", "IKEv2: the CA certificate (PEM) that signed the server's certificate; \"\" for a public one")
	f.StringVar(&e.pskRef, "psk-ref", "", "L2TP, IPsec, IKEv2: the pre-shared key (IPsec: the group password)")
	f.StringVar(&e.localID, "id", "", "IPsec: the group name; IKEv2: your identity")
	f.StringVar(&e.remoteID, "remote-id", "", "IKEv2: the server's identity")
	f.StringVar(&e.user, "user", "", "user name for the VPN login")
	f.StringVar(&e.passwordRef, "password-ref", "", "password as secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME | azure-kv:VAULT/NAME")
	f.BoolVar(&e.mfa, "mfa", false, "the login needs a person (MFA, SSO)")
	f.BoolVar(&e.legacyCrypto, "legacy-crypto", false, "L2TP, IPsec: also offer 3DES and DH groups 2 and 5, for old servers (weak; turning it on needs a person's yes)")
	f.BoolVar(&e.allowPAP, "allow-pap", false, "L2TP: let the server pick PAP, which hands it your password itself (turning it on needs a person's yes)")
	f.StringVar(&e.notes, "notes", "", "free-form notes")
	f.StringSliceVar(&e.addGroups, "add-group", nil, "put it in these groups (comma-separated)")
	f.StringSliceVar(&e.rmGroups, "rm-group", nil, "take it out of these groups")
	f.StringSliceVar(&e.addTags, "add-tag", nil, "add these tags (comma-separated)")
	f.StringSliceVar(&e.rmTags, "rm-tag", nil, "remove these tags")
	shortAlias(f, "group", "g", "add-group")
	shortAlias(f, "tag", "t", "add-tag")

}

// withVpnGuards adds to vpn edit's apply what needs a person: turning on
// --legacy-crypto or --allow-pap (vpnOptIns), and, for an AI agent, a
// secret the VPN now sends somewhere new (guardVpnSends). res is the VPN
// apply changed, the same one it stored outside --dry-run.
func withVpnGuards(name string, changed func(string) bool, res **store.Vpn, legacy, pap bool, apply func(*store.State) error) func(*store.State) error {
	return func(s *store.State) error {
		old := s.Vpns[name] // apply stores a changed copy
		if err := apply(s); err != nil {
			return err
		}
		if err := vpnOptIns(*res, changed, legacy, pap); err != nil {
			return err
		}
		return guardVpnSends(old, *res, "")
	}
}

// vpnOptIns sets --legacy-crypto and --allow-pap on v (vpn add and edit).
// They weaken the VPN's login, so turning one on needs a person's yes
// (guardSafety); turning it off does not.
func vpnOptIns(v *store.Vpn, changed func(string) bool, legacy, pap bool) error {
	for flag, kinds := range map[string][]string{"legacy-crypto": {"l2tp", "ipsec"}, "allow-pap": {"l2tp"}} {
		if changed(flag) && !oneOf(v.Kind, kinds...) {
			return out.Usage("--%s is not used by %s VPNs", flag, v.Kind)
		}
	}
	if changed("legacy-crypto") {
		if legacy && !v.LegacyCrypto {
			if err := guardSafety("allowing old, weak IKEv1 ciphers (3DES, DH groups 2 and 5) for VPN " + v.Name); err != nil {
				return err
			}
		}
		v.LegacyCrypto = legacy
	}
	if changed("allow-pap") {
		if pap && !v.AllowPAP {
			if err := guardSafety("letting VPN " + v.Name + " log in with PAP, which hands the server your password itself"); err != nil {
				return err
			}
		}
		v.AllowPAP = pap
	}
	return nil
}

// usedByText is a USED BY cell that fits a table: "48 (app-01, app-02, +46)".
func usedByText(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ",")
	}
	return fmt.Sprintf("%d (%s, %s, +%d)", len(names), names[0], names[1], len(names)-2)
}
