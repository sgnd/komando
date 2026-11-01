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
		Short: "VPNs komando connects by itself when a --via path needs them (several at once)",
		Long: `Add a VPN once, then put it first in --via. A command that needs it
connects it, using the login stored in the vault:

  komando vpn add office wireguard --config ~/Downloads/office.conf
  komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
  komando host add app admin@10.0.0.5 --via office,bastion
  komando exec app -- uptime

VPNs with --mfa need a person: run ` + "`komando vpn up NAME`" + ` once and later
commands (and agents) reuse that session. komando never answers MFA.

Kinds (also: pritunl = openvpn; l2tp, ipsec, ikev2 = system):
` + strings.Join(kinds, "\n"),
	}
	c.AddCommand(vpnAddCmd(), vpnShowCmd(), vpnRmCmd(), vpnUpCmd(), vpnDownCmd(), vpnStatusCmd(), vpnServeCmd(),
		alias(listCmdFor("vpn"), "list kind:vpn"), alias(testCmdFor("vpn"), "test"))
	return c
}

// openvpnScripts are .ovpn directives that run programs. OpenVPN runs as
// root, so komando refuses configs that use them.
var openvpnScripts = []string{"up", "down", "route-up", "route-pre-down", "ipchange", "script-security",
	"client-connect", "client-disconnect", "learn-address", "tls-verify", "auth-user-pass-verify", "plugin", "setenv-safe"}

func checkOVPN(cfg string) error {
	for n, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) > 0 && slices.Contains(openvpnScripts, strings.TrimLeft(strings.ToLower(f[0]), "-")) {
			return fmt.Errorf("line %d: %q runs a program as root; komando does not allow it", n+1, f[0])
		}
	}
	return nil
}

func vpnAddCmd() *cobra.Command {
	var config, address, portal, service, server, user, passwordRef, check, notes string
	var groups, tags []string
	var overwrite, mfa, osMode bool
	c := &cobra.Command{
		Use:   "add NAME KIND",
		Short: "Add a VPN (see `komando vpn --help` for the kinds)",
		Example: `  komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
  komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
  komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
  komando vpn add tailnet tailscale --password-ref secret:ts-authkey
  komando vpn add corp system --service "Corp VPN" --check 10.20.0.1:443
  komando vpn add lab socks --address 127.0.0.1:1080`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, kind := args[0], strings.ToLower(args[1])
			switch kind {
			case "pritunl":
				kind = "openvpn"
			case "l2tp", "ipsec", "ikev2":
				kind = "system"
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
			for _, r := range []string{passwordRef} {
				if r != "" && !vault.ValidRef(r) {
					return out.Usage("invalid --password-ref %q: %s", r, vault.RefHelp())
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
					return "", out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the path of the VPN's config file", "%v", err)
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
			case kind == "socks":
				if err = need("address", address != ""); err != nil {
					return err
				}
				if _, _, err := net.SplitHostPort(address); err != nil {
					return out.Usage("--address must be host:port")
				}
				v.Address = address
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
			case k.Protocol != "": // the openconnect family
				if err = need("portal", portal != ""); err != nil {
					return err
				}
				v.Portal = portal
				used["user"], used["password-ref"] = true, true
				if passwordRef == "" {
					v.MFA = true // without a stored password a person types it
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
				v.ConfigRef, v.OSMode = "secret:"+name+"-config", osMode
				secrets[name+"-config"] = text
				used["user"], used["password-ref"] = true, true
			}
			if osMode && kind != "openvpn" {
				return out.Usage("--os-mode is for openvpn")
			}
			for flag, val := range map[string]string{"config": config, "address": address, "portal": portal, "service": service,
				"server": server, "user": user, "password-ref": passwordRef} {
				if val != "" && !used[flag] {
					return out.Usage("--%s is not used by %s VPNs", flag, kind)
				}
			}
			now := time.Now().UTC()
			v.CreatedAt, v.UpdatedAt = now, now
			if g.dryRun {
				out.P.Print("vpn.add", v, nil)
				return nil
			}
			if err := store.Update(func(s *store.State) error { return checkNewName(s, "vpn", name, overwrite) }); err != nil {
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
			if len(secrets) > 0 && config != "" {
				notes = append(notes, config+" still holds the keys that are now in the vault; delete it if you no longer need it")
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
			out.P.Print("vpn.add", res, nil)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&config, "config", "", "wireguard: the .conf file; openvpn: the .ovpn file (both kept in the vault)")
	f.StringVar(&address, "address", "", "socks: host:port of the proxy")
	f.StringVar(&portal, "portal", "", "globalprotect, fortinet, anyconnect, pulse, f5: the VPN server or portal")
	f.StringVar(&service, "service", "", "system: the VPN's name in your computer's settings, so `vpn up` can connect it")
	f.StringVar(&server, "server", "", "tailscale: a Headscale login server URL")
	f.StringVar(&user, "user", "", "user name for the VPN login")
	f.StringVar(&passwordRef, "password-ref", "", "password (tailscale: auth key) as secret:NAME | env:VAR | file:PATH | op://... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME")
	f.BoolVar(&osMode, "os-mode", false, "openvpn: run it on this computer with sudo instead of in a Docker container (changes this computer's network)")
	f.BoolVar(&mfa, "mfa", false, "the login needs a person (MFA, SSO): only `vpn up` by a human connects it")
	f.StringVar(&check, "check", "", "host:port reachable only through this VPN (used by `komando test`, needed for system and openvpn)")
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
		Use:   "rm NAME",
		Short: "Remove a VPN from komando (its keys stay in the vault until `komando secret rm`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := store.Update(func(s *store.State) error {
				if _, ok := s.Vpns[args[0]]; !ok {
					return out.NotFound("vpn", args[0])
				}
				if users := vpnUsers(s, args[0]); len(users) > 0 {
					return out.Errf(out.ExitConflict, "VPN_IN_USE", "change their --via first", "VPN %s is on the --via path of %s", args[0], strings.Join(users, ", "))
				}
				if sess := s.Sessions[args[0]]; sess != nil {
					netx.StopSession(sess)
					delete(s.Sessions, args[0])
				}
				delete(s.Vpns, args[0])
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "vpn.rm", []string{args[0]}, "", true, nil)
			out.P.Print("vpn.rm", map[string]any{"removed": args[0]}, nil)
			return nil
		},
	}
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
	case "socks":
		return v.Address
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
