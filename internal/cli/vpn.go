package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/openvpn"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando vpn` keeps the networks that targets are reached through. A VPN
// is used by putting its name first in a --via path; komando opens it inside
// its own process for that command only (docs/design/network.md).

func vpnCmd() *cobra.Command {
	var kinds []string
	for _, k := range netx.KindNames() {
		kinds = append(kinds, fmt.Sprintf("  %-13s %s", k, netx.Kinds[k].Desc))
	}
	c := &cobra.Command{
		Use:   "vpn",
		Short: "VPNs komando connects by itself when a --via path needs one",
		Long: `Add a VPN once, then put it first in --via. A command that needs it
connects it, using the login stored in the vault:

  komando vpn add office wireguard --config ~/Downloads/office.conf
  komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
  komando host add app admin@10.0.0.5 --via office,bastion
  komando exec app -- uptime

VPNs with --mfa need a person: run ` + "`komando vpn up NAME`" + ` once and later
commands (and agents) reuse that session. komando never answers MFA.

Kinds (also: pritunl = openvpn; cisco = ipsec):
` + strings.Join(kinds, "\n"),
	}
	c.AddCommand(vpnAddCmd(), vpnShowCmd(), vpnEditCmd(), vpnMvCmd(), vpnRmCmd(), vpnUpCmd(), vpnDownCmd(), vpnStatusCmd(), vpnServeCmd(),
		alias(listCmdFor("vpn"), "list kind:vpn"), alias(testCmdFor("vpn"), "test"))
	return c
}

func vpnAddCmd() *cobra.Command {
	var config, address, portal, service, server, user, passwordRef, check, notes, pskRef, localID, remoteID, ca string
	var groups, tags []string
	var overwrite, mfa, osMode bool
	c := &cobra.Command{
		Use:   "add NAME KIND",
		Short: "Add a VPN (see `komando vpn --help` for the kinds)",
		Example: `  komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
  komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
  komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
  komando vpn add tailnet tailscale --password-ref secret:ts-authkey
  komando vpn add kantor l2tp --server vpn.kantor.id --psk-ref secret:kantor-psk --user budi --password-ref secret:kantor
  komando vpn add asa ipsec --server asa.client.com --id staff --psk-ref secret:asa-group --user budi
  komando vpn add cloud ikev2 --server vpn.example.com --user budi --password-ref secret:cloud
  komando vpn add corp system --service "Corp VPN" --check 10.20.0.1:443
  komando vpn add lab socks --address 127.0.0.1:1080
  komando vpn add office proxy --address proxy.corp.example:3128   # a company HTTP proxy`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, kind := args[0], strings.ToLower(args[1])
			switch kind {
			case "pritunl":
				kind = "openvpn"
			case "cisco", "xauth":
				kind = "ipsec"
			}
			if err := validName("vpn", name); err != nil {
				return err
			}
			k, ok := netx.Kinds[kind]
			if !ok {
				return out.Usage("unknown VPN kind %q (see `komando vpn --help`)", kind)
			}
			if check != "" {
				if _, _, err := net.SplitHostPort(check); err != nil {
					return out.Usage("--check must be host:port")
				}
			}
			for _, r := range []string{passwordRef, pskRef} {
				if r != "" && !vault.ValidRef(r) {
					return out.Usage("invalid reference %q: %s", r, vault.RefHelp())
				}
			}
			v := &store.Vpn{Name: name, Kind: kind, Check: check, User: user, KeyRef: passwordRef, MFA: mfa,
				Groups: dedupe(groups), Tags: dedupe(tags), Notes: notes}
			used := map[string]bool{}
			need := func(flag string, ok bool) error {
				used[flag] = true
				if !ok {
					return out.Usage("%s needs --%s", kind, flag)
				}
				return nil
			}
			secrets := map[string]string{}
			readConfig := func() (string, error) {
				b, err := os.ReadFile(expandHome(config))
				if err != nil {
					return "", localFileErr("FILE_NOT_FOUND", err, "give the path of the VPN's config file")
				}
				return string(b), nil
			}
			var err error
			switch {
			case kind == "wireguard":
				if err = need("config", config != ""); err != nil {
					return err
				}
				text, err := readConfig()
				if err != nil {
					return err
				}
				clean, priv, psk, err := netx.StripWGKeys(text)
				if err != nil {
					return out.Errf(out.ExitUsage, "VPN_CONFIG", "check the file is a WireGuard (wg-quick) config", "%s: %v", config, err)
				}
				v.Config, v.KeyRef = clean, "secret:"+name+"-key"
				secrets[name+"-key"] = priv
				if psk != "" {
					v.PSKRef = "secret:" + name + "-psk"
					secrets[name+"-psk"] = psk
				}
				used["password-ref"] = passwordRef == ""
			case kind == "socks" || kind == "proxy":
				if err = need("address", address != ""); err != nil {
					return err
				}
				if v.Address, err = vpnAddress(kind, address); err != nil {
					return err
				}
				used["user"], used["password-ref"] = true, true
				if user != "" && passwordRef == "" {
					return out.Usage("--user needs --password-ref (the proxy's password)")
				}
			case kind == "system":
				if err = need("check", check != ""); err != nil {
					return err
				}
				v.Service, used["service"] = service, true
			case kind == "tailscale":
				v.Server, used["server"], used["password-ref"] = server, true, true
				if passwordRef == "" {
					v.MFA = true // no auth key: a person logs in through the browser
				}
			case k.Protocol != "" || netx.BuiltinSSL(kind): // corporate SSL VPNs: a portal
				if err = need("portal", portal != ""); err != nil {
					return err
				}
				if strings.HasPrefix(portal, "-") {
					return out.Usage("--portal must be a server name or URL")
				}
				v.Portal = portal
				used["user"], used["password-ref"] = true, true
				if passwordRef == "" {
					v.MFA = true // without a stored password a person types it
				}
			case oneOf(kind, "l2tp", "ipsec", "ikev2"):
				if err = need("server", server != ""); err != nil {
					return err
				}
				if strings.HasPrefix(server, "-") || strings.Contains(server, "/") {
					return out.Usage("--server must be a host name or address (host or host:port)")
				}
				v.Server, v.PSKRef, used["psk-ref"], used["user"], used["password-ref"] = server, pskRef, true, true, true
				switch kind {
				case "l2tp":
					if pskRef == "" || user == "" {
						return out.Usage("l2tp needs --psk-ref (the IPsec pre-shared key) and --user (the L2TP login); add --password-ref, or type the password at `komando vpn up`")
					}
				case "ipsec":
					if pskRef == "" {
						return out.Usage("ipsec needs --psk-ref (the group password) and usually --id (the group name) and --user")
					}
					v.LocalID, used["id"] = localID, true
				case "ikev2":
					if pskRef == "" && user == "" {
						return out.Usage("ikev2 needs --psk-ref (a pre-shared key) or --user (an EAP login checked with the server's certificate)")
					}
					v.LocalID, v.RemoteID, used["id"], used["remote-id"], used["ca"] = localID, remoteID, true, true, true
					if ca != "" {
						b, err := os.ReadFile(expandHome(ca))
						if err != nil {
							return localFileErr("FILE_NOT_FOUND", err, "give the path of the CA certificate (PEM)")
						}
						if !strings.Contains(string(b), "-----BEGIN CERTIFICATE-----") {
							return out.Usage("--ca must be a PEM certificate file")
						}
						v.CA = string(b)
					}
				}
				if user != "" && passwordRef == "" {
					v.MFA = true // a person types the password at `vpn up`
				}
			case kind == "openvpn":
				if err = need("config", config != ""); err != nil {
					return err
				}
				if err = need("check", check != ""); err != nil {
					return err
				}
				text, err := readConfig()
				if err != nil {
					return err
				}
				if err := checkOVPN(text); err != nil {
					return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "remove that line from the .ovpn file", "%s: %v", config, err)
				}
				if !osMode { // komando's own client must understand every line
					p, err := openvpn.Parse(text)
					if err != nil {
						return out.Errf(out.ExitUsage, "OVPN_UNSUPPORTED", "change the profile, or tell the komando project which option you need", "%s: %v", config, err)
					}
					if p.AuthUserPass && user == "" {
						return out.Usage("%s logs in with a user name and password (auth-user-pass): add --user, and --password-ref (or --mfa to type it at `vpn up`)", config)
					}
				}
				v.ConfigRef, v.OSMode = "secret:"+name+"-config", osMode
				secrets[name+"-config"] = text
				used["user"], used["password-ref"] = true, true
			}
			if osMode && kind != "openvpn" {
				return out.Usage("--os-mode is for openvpn")
			}
			for flag, val := range map[string]string{"config": config, "address": address, "portal": portal, "service": service,
				"server": server, "user": user, "password-ref": passwordRef, "psk-ref": pskRef, "id": localID, "remote-id": remoteID, "ca": ca} {
				if val != "" && !used[flag] {
					return out.Usage("--%s is not used by %s VPNs", flag, kind)
				}
			}
			now := time.Now().UTC()
			v.CreatedAt, v.UpdatedAt = now, now
			warnings := refWarnings(v.KeyRef, v.PSKRef)
			if g.dryRun {
				// the same name checks the real add makes
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := vpnAddCheck(st, name, secrets, overwrite); err != nil {
					return err
				}
				res := map[string]any{"would_add": v}
				if len(warnings) > 0 {
					res["warnings"] = warnings
				}
				out.P.Print("vpn.add", res, nil)
				return nil
			}
			if err := store.Update(func(s *store.State) error { return vpnAddCheck(s, name, secrets, overwrite) }); err != nil {
				return err
			}
			for n, val := range secrets {
				if err := vault.Set(n, val); err != nil {
					return err
				}
			}
			if err := store.Update(func(s *store.State) error {
				if err := checkNewName(s, "vpn", name, overwrite); err != nil {
					return err
				}
				s.Vpns[name] = v
				return nil
			}); err != nil {
				return err
			}
			audit(nil, "vpn.add", []string{name}, "", true, map[string]any{"kind": kind, "mfa": v.MFA})
			res := map[string]any{"vpn": v}
			var notes []string
			if kind == "wireguard" || kind == "openvpn" && ovpnHasKeys(secrets[name+"-config"]) {
				notes = append(notes, config+" still holds the keys that are now in the vault; delete it if you no longer need it")
			}
			if v.Check == "" {
				notes = append(notes, "without --check, `komando vpn up` and `komando test` cannot tell whether the VPN works; add one with `komando vpn edit "+name+" --check HOST:PORT`")
			}
			if v.MFA {
				notes = append(notes, "a person logs in with `komando vpn up "+name+"`; later commands reuse that session")
			}
			if len(k.Client) > 0 {
				notes = append(notes, "needs "+strings.Join(k.Client, " and ")+" installed (`komando doctor` checks)")
			}
			if len(notes) > 0 {
				res["notes"] = notes
			}
			if len(warnings) > 0 {
				res["warnings"] = warnings
			}
			out.P.Print("vpn.add", res, nil)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&config, "config", "", "wireguard: the .conf file; openvpn: the .ovpn file (both kept in the vault)")
	f.StringVar(&address, "address", "", "socks: host:port of the proxy; proxy: host:port or http(s)://host:port")
	f.StringVar(&portal, "portal", "", "globalprotect, fortinet, anyconnect, pulse, f5: the VPN server or portal")
	f.StringVar(&service, "service", "", "system: the VPN's name in your computer's settings, so 'vpn up' can connect it")
	f.StringVar(&server, "server", "", "l2tp, ipsec, ikev2: the VPN server (host or host:port); tailscale: a Headscale login server URL")
	f.StringVar(&pskRef, "psk-ref", "", "l2tp, ipsec, ikev2: the pre-shared key (ipsec: the group password), as a reference like --password-ref")
	f.StringVar(&localID, "id", "", "ipsec: the group name; ikev2: your identity (default: --user, or your address)")
	f.StringVar(&remoteID, "remote-id", "", "ikev2: the server's identity, if not its --server name")
	f.StringVar(&ca, "ca", "", "ikev2: the CA certificate (PEM) that signed the server's certificate, if not a public one")
	f.StringVar(&user, "user", "", "user name for the VPN login")
	f.StringVar(&passwordRef, "password-ref", "", "password (tailscale: auth key) as secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	f.BoolVar(&osMode, "os-mode", false, "openvpn: deprecated; run the openvpn program on this computer with sudo (changes its network) instead of komando's own client")
	f.BoolVar(&mfa, "mfa", false, "the login needs a person (MFA, SSO): only 'vpn up' by a human connects it")
	f.StringVar(&check, "check", "", "host:port reachable only through this VPN (vpn up and test connect to it; needed for system and openvpn)")
	f.StringSliceVarP(&groups, "group", "g", nil, "group(s)")
	f.StringSliceVarP(&tags, "tag", "t", nil, "tag(s)")
	f.StringVar(&notes, "notes", "", "free-form notes")
	f.BoolVar(&overwrite, "overwrite", false, "replace a VPN with the same name")
	return c
}

func vpnShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Show a VPN (keys stay in the vault)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			v, ok := st.Vpns[args[0]]
			if !ok {
				return out.NotFound("vpn", args[0])
			}
			out.P.Print("vpn.show", map[string]any{"vpn": v, "used_by": vpnUsers(st, v.Name)}, nil)
			return nil
		},
	}
}

func vpnRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME...",
		Short: "Remove VPNs from komando (their keys stay in the vault)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// all or nothing, like host rm: a VPN in use stops the whole call
			check := func(s *store.State) error {
				for _, name := range args {
					if _, ok := s.Vpns[name]; !ok {
						return out.NotFound("vpn", name)
					}
					if users := vpnUsers(s, name); len(users) > 0 {
						return out.Errf(out.ExitConflict, "VPN_IN_USE", "change their --via first", "VPN %s is on the --via path of %s", name, strings.Join(users, ", "))
					}
				}
				return nil
			}
			// one name: the name itself, as before; several: the list
			names := func() any {
				if len(args) == 1 {
					return args[0]
				}
				return args
			}
			if g.dryRun { // the same checks as the real removal
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := check(st); err != nil {
					return err
				}
				out.P.Print("vpn.rm", map[string]any{"would_remove": names()}, nil)
				return nil
			}
			err := store.Update(func(s *store.State) error {
				if err := check(s); err != nil {
					return err
				}
				for _, name := range args {
					if sess := s.Sessions[name]; sess != nil {
						if err := netx.StopSession(sess); err != nil {
							return out.Errf(out.ExitError, "VPN_STOP_FAILED", "disconnect it first with `komando vpn down "+name+"`", "%v", err)
						}
						delete(s.Sessions, name)
					}
					delete(s.Vpns, name)
				}
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "vpn.rm", args, "", true, nil)
			out.P.Print("vpn.rm", map[string]any{"removed": names()}, nil)
			return nil
		},
	}
}

// ovpnHasKeys: the OpenVPN config holds a private key or shared secret inline.
func ovpnHasKeys(cfg string) bool {
	for _, t := range []string{"<key>", "<secret>", "<pkcs12>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>"} {
		if strings.Contains(cfg, t) {
			return true
		}
	}
	return false
}

// vpnUsers lists the servers and conns whose --via path names the VPN.
func vpnUsers(st *store.State, name string) []string {
	var users []string
	for _, h := range st.SortedHosts() {
		if slices.Contains(viaChain(h.Via), name) {
			users = append(users, h.Name)
		}
	}
	for _, c := range st.SortedConns() {
		if slices.Contains(viaChain(c.Via), name) {
			users = append(users, c.Name)
		}
	}
	return users
}

// vpnWhere is a VPN's address for `komando list`.
func vpnWhere(v *store.Vpn) string {
	switch v.Kind {
	case "wireguard":
		if c, err := netx.ParseWG(v.Config); err == nil && c.Peers[0].Endpoint != "" {
			return c.Peers[0].Endpoint
		}
	case "socks", "proxy":
		return v.Address
	case "l2tp", "ipsec", "ikev2":
		return v.Server
	}
	return dash(v.Check)
}

// testVpn opens the VPN and, when it has --check, connects to that address
// through it.
func testVpn(ctx context.Context, st *store.State, v *store.Vpn) targetTest {
	r := targetTest{Name: v.Name, Kind: "vpn"}
	t0 := time.Now()
	timeout := sshOpts(st).ConnectTimeout
	dial, closer, err := netx.Open(ctx, v, timeout)
	if err != nil {
		r.Error = toErr(err)
		return r
	}
	defer closer.Close()
	detail := map[string]any{"kind": v.Kind}
	if v.Check != "" && v.Kind != "system" { // system already checked it in Open
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, err := dial(cctx, "tcp", v.Check)
		if err != nil {
			r.Error = toErr(err)
			return r
		}
		c.Close()
		detail["checked"] = v.Check
	} else if v.Check == "" {
		detail["note"] = "no --check address, so only the configuration was checked"
	}
	r.OK, r.LatencyMS, r.Detail = true, time.Since(t0).Milliseconds(), detail
	return r
}

// vpnAddress checks a socks or proxy VPN's --address: host:port, or for an
// HTTP proxy also an http(s):// URL, kept as one.
func vpnAddress(kind, address string) (string, error) {
	if kind == "proxy" {
		pu, err := netx.ProxyURL(address)
		if err != nil {
			return "", out.Usage("%v", err)
		}
		return pu.String(), nil
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return "", out.Usage("--address must be host:port")
	}
	return address, nil
}
