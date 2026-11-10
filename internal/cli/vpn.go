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
	var overwrite, mfa, osMode, legacyCrypto, allowPAP, askPw, askPsk bool
	c := &cobra.Command{
		Use:   "add NAME KIND",
		Short: "Add a VPN (see `komando vpn --help` for the kinds)",
		Example: `  komando vpn add office wireguard --config ~/Downloads/office.conf --check 10.0.0.5:22
  komando vpn add client-x globalprotect --portal vpn.client.com --user budi --password-ref secret:client-x --mfa
  komando vpn add kantor openvpn --config kantor.ovpn --user budi --password-ref secret:kantor --check 10.8.0.1:22
  komando vpn add tailnet tailscale --password-ref secret:ts-authkey
  komando vpn add kantor l2tp --server vpn.kantor.id --psk-ref secret:kantor-psk --user budi --ask-password   # type the password now (hidden)
  komando vpn add old-office l2tp --server vpn.example.com --psk-ref secret:old-psk --user alice --legacy-crypto --allow-pap
  komando vpn add asa ipsec --server asa.client.com --id staff --psk-ref secret:asa-group --user budi
  komando vpn add cloud ikev2 --server vpn.example.com --user budi --password-ref secret:cloud
  komando vpn add corp system --service "Corp VPN" --check 10.20.0.1:443
  komando vpn add lab socks --address 127.0.0.1:1080
  komando vpn add office proxy --address proxy.corp.example:3128   # a company HTTP proxy`,
		Args: formArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return formOrUsage(cmd, "vpn", "komando vpn add office wireguard --config ~/Downloads/office.conf")
			}
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
			if err := vpnAskPasswordRef(cmd, name, kind, askPw, &passwordRef); err != nil {
				return err
			}
			if err := vpnAskPSKRef(cmd, name, kind, askPsk, &pskRef); err != nil {
				return err
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
			var ovpnWarn []string
			ovpnServers := ""
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
				if err = vpnAddIPsec(v, used, server, pskRef, localID, remoteID, ca); err != nil {
					return err
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
				if ovpnServers, err = ovpnRemotes(text); err != nil {
					return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "remove that line from the .ovpn file", "%s: %v", config, err).NoFlag()
				}
				if !osMode { // komando's own client must understand every line
					p, err := openvpn.Parse(text)
					if err != nil {
						return out.Errf(out.ExitUsage, "OVPN_UNSUPPORTED", "change the profile, or report the option you need at "+releaseSite+"/issues", "%s: %v", config, err)
					}
					if p.AuthUserPass && user == "" {
						return out.Usage("%s logs in with a user name and password (auth-user-pass): add --user, and --password-ref (or --mfa to type it at `vpn up`)", config)
					}
					ovpnWarn = p.Warnings
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
			warnings := append(refWarnings(unlessAsked(v.KeyRef, askPw), unlessAsked(v.PSKRef, askPsk)), ovpnWarn...)
			// the name and the VPN's vault secrets, and what needs a person: a weaker login, a secret sent to a new place
			check := func(s *store.State) error {
				if err := vpnAddCheck(s, name, secrets, overwrite); err != nil {
					return err
				}
				if err := vpnOptIns(v, cmd.Flags().Changed, legacyCrypto, allowPAP); err != nil {
					return err
				}
				return guardVpnSends(s.Vpns[name], v, ovpnServers)
			}
			if g.dryRun { // the same checks the real add makes
				st, err := loadState()
				if err != nil {
					return err
				}
				if err := check(st); err != nil {
					return err
				}
				res := map[string]any{"would_add": v}
				if len(warnings) > 0 {
					res["warnings"] = warnings
				}
				out.P.Print("vpn.add", res, nil)
				return nil
			}
			undoPw, err := vpnAskPassword(cmd, name, askPw, askPsk, check)
			if err != nil {
				return err
			}
			if err := vpnAddSave(v, secrets, overwrite, check); err != nil {
				undoPw()
				return err
			}
			audit(nil, "vpn.add", []string{name}, "", true, map[string]any{"kind": kind, "mfa": v.MFA})
			res := map[string]any{"vpn": v, "next": "komando vpn up " + name}
			if notes := vpnAddNotes(v, config, ovpnHasKeys(secrets[name+"-config"])); len(notes) > 0 {
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
	f.StringVar(&config, "config", "", "WireGuard: the .conf file; OpenVPN: the .ovpn file (both kept in the vault)")
	f.StringVar(&address, "address", "", "SOCKS: host:port of the proxy; proxy: host:port or http(s)://host:port")
	f.StringVar(&portal, "portal", "", "GlobalProtect, Fortinet, AnyConnect, Pulse, F5: the VPN server or portal")
	f.StringVar(&service, "service", "", "System VPN: its name in your computer's settings, so 'vpn up' can connect it")
	f.StringVar(&server, "server", "", "L2TP, IPsec, IKEv2: the VPN server (host or host:port); Tailscale: a Headscale login server URL")
	f.StringVar(&pskRef, "psk-ref", "", "L2TP, IPsec, IKEv2: the pre-shared key (IPsec: the group password), as a reference like --password-ref")
	f.StringVar(&localID, "id", "", "IPsec: the group name; IKEv2: your identity (default: --user, or your address)")
	f.StringVar(&remoteID, "remote-id", "", "IKEv2: the server's identity, if not its --server name")
	f.StringVar(&ca, "ca", "", "IKEv2: the CA certificate (PEM) that signed the server's certificate, if not a public one")
	f.StringVar(&user, "user", "", "user name for the VPN login")
	f.StringVar(&passwordRef, "password-ref", "", "password (Tailscale: auth key) as secret:NAME | env:VAR | file:PATH | op://... | bw://... | kdbx:... | vault:PATH#FIELD | aws-sm:NAME | gcp-sm:NAME | azure-kv:VAULT/NAME")
	askPasswordFlag(c, &askPw)
	f.BoolVar(&askPsk, "ask-psk", false, "L2TP, IPsec, IKEv2: type the pre-shared key now (hidden, a person at a terminal); it is stored in the vault as secret:NAME-psk and used as --psk-ref")
	f.BoolVar(&osMode, "os-mode", false, "OpenVPN: deprecated; run the openvpn program on this computer with sudo (changes its network) instead of komando's own client")
	f.BoolVar(&mfa, "mfa", false, "the login needs a person (MFA, SSO): only 'vpn up' run by a person connects it")
	f.BoolVar(&legacyCrypto, "legacy-crypto", false, "L2TP, IPsec: also offer 3DES and DH groups 2 and 5, for old servers (weak; needs a person's yes)")
	f.BoolVar(&allowPAP, "allow-pap", false, "L2TP: let the server pick PAP, which hands it your password itself (needs a person's yes)")
	f.StringVar(&check, "check", "", "host:port reachable only through this VPN (vpn up and test connect to it; needed for system and openvpn)")
	f.StringSliceVarP(&groups, "group", "g", nil, "put it in these groups (comma-separated)")
	f.StringSliceVarP(&tags, "tag", "t", nil, "tags, e.g. prod (comma-separated)")
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
			// one name: the name itself; several: the list
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
			var unused []string
			err := store.Update(func(s *store.State) error {
				if err := check(s); err != nil {
					return err
				}
				var refs []string
				for _, name := range args {
					if v := s.Vpns[name]; v != nil {
						refs = append(refs, v.KeyRef, v.PSKRef, v.ConfigRef)
					}
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
				return err
			}
			audit(nil, "vpn.rm", args, "", true, nil)
			res := map[string]any{"removed": names()} // one VPN stays a string, so scripts that read it keep working
			if len(unused) > 0 {
				res["secrets_unused"] = unused
			}
			out.P.Print("vpn.rm", textAs{res, rmResult{Removed: args, SecretsUnused: unused}}, nil)
			return nil
		},
	}
}

// vpnAddIPsec fills in an l2tp, ipsec or ikev2 VPN v from vpn add's flags
// (v.User and v.KeyRef are set already) and marks in used the flags it
// takes.
func vpnAddIPsec(v *store.Vpn, used map[string]bool, server, pskRef, localID, remoteID, ca string) (err error) {
	if strings.HasPrefix(server, "-") || strings.Contains(server, "/") {
		return out.Usage("--server must be a host name or address (host or host:port)")
	}
	v.Server, v.PSKRef, used["psk-ref"], used["user"], used["password-ref"] = server, pskRef, true, true, true
	switch v.Kind {
	case "l2tp":
		if pskRef == "" || v.User == "" {
			return out.Usage("l2tp needs --psk-ref (the IPsec pre-shared key) and --user (the L2TP login); add --password-ref or --ask-password, or type the password at `komando vpn up`")
		}
	case "ipsec":
		if pskRef == "" {
			return out.Usage("ipsec needs --psk-ref (the group password) and usually --id (the group name) and --user")
		}
		v.LocalID, used["id"] = localID, true
	case "ikev2":
		if pskRef == "" && v.User == "" {
			return out.Usage("ikev2 needs --psk-ref (a pre-shared key) or --user (an EAP login checked with the server's certificate)")
		}
		v.LocalID, v.RemoteID, used["id"], used["remote-id"], used["ca"] = localID, remoteID, true, true, true
		if v.CA, err = readVpnCA(ca); err != nil {
			return err
		}
	}
	if v.User != "" && v.KeyRef == "" {
		v.MFA = true // a person types the password at `vpn up`
	}
	return nil
}

// vpnAskPasswordRef is the --password-ref that vpn add --ask-password
// gives the VPN: secret:NAME-pass, stored once the other checks pass. It
// is refused with --password-ref, and for the kinds that take no password.
func vpnAskPasswordRef(cmd *cobra.Command, name, kind string, askPw bool, ref *string) error {
	if !askPw {
		return nil
	}
	if cmd.Flags().Changed("password-ref") {
		return out.Usage("use --ask-password or --password-ref, not both")
	}
	if oneOf(kind, "wireguard", "system", "tailscale") {
		return out.Usage("--ask-password is not used by %s VPNs (a tailscale auth key: `komando secret set %s-authkey`, then --password-ref secret:%s-authkey)", kind, name, name)
	}
	*ref = "secret:" + name + "-pass"
	return nil
}

// vpnAskPSKRef is vpnAskPasswordRef for --ask-psk: the pre-shared key of
// an l2tp, ipsec or ikev2 VPN, stored as secret:NAME-psk.
func vpnAskPSKRef(cmd *cobra.Command, name, kind string, askPsk bool, ref *string) error {
	if !askPsk {
		return nil
	}
	if cmd.Flags().Changed("psk-ref") {
		return out.Usage("use --ask-psk or --psk-ref, not both")
	}
	if !oneOf(kind, "l2tp", "ipsec", "ikev2") {
		return out.Usage("--ask-psk is for l2tp, ipsec and ikev2 VPNs, not %s", kind)
	}
	*ref = "secret:" + name + "-psk"
	return nil
}

// unlessAsked is ref, or "" when --ask-password stores it later: no
// warning that it is not in the vault yet.
func unlessAsked(ref string, asked bool) string {
	if asked {
		return ""
	}
	return ref
}

// vpnAskPassword asks the password and the pre-shared key of vpn add
// --ask-password and --ask-psk once every check that can refuse the add
// (check: the name, the VPN's own secrets, the weaker settings it asks for,
// where its secrets go) passes on the state as it is now, so a person is
// not asked for a secret the add then refuses. undo takes them back.
func vpnAskPassword(cmd *cobra.Command, name string, askPw, askPsk bool, check func(*store.State) error) (func(), error) {
	none := func() {}
	if !askPw && !askPsk {
		return none, nil
	}
	if !interactive() { // nobody to ask: NEEDS_PERSON or NEEDS_TERMINAL says so first, nothing is stored
		first := askPasswordSecret
		if askPsk {
			first = askPSKSecret
		}
		if _, _, err := askSecretNow(cmd, "vpn", name, first); err != nil {
			return none, err
		}
	}
	st, err := loadState()
	if err != nil {
		return none, err
	}
	if err := check(st); err != nil {
		return none, err
	}
	undoPsk := none
	if askPsk {
		if undoPsk, err = vpnAskSecret(cmd, name, askPSKSecret); err != nil {
			return none, err
		}
	}
	if !askPw {
		return undoPsk, nil
	}
	undoPw, err := vpnAskSecret(cmd, name, askPasswordSecret)
	if err != nil {
		undoPsk()
		return none, err
	}
	return func() { undoPw(); undoPsk() }, nil
}

// vpnAskSecret asks one secret of vpn add and stores it as NAME-suffix.
// Its undo removes a secret that was new, and puts the old value back in
// one it replaced (vpn add --overwrite), so a refused add changes nothing.
func vpnAskSecret(cmd *cobra.Command, name string, a askSecret) (func(), error) {
	sec := name + "-" + a.suffix
	old, getErr := vault.Get(sec)
	_, undo, err := askSecretNow(cmd, "vpn", name, a)
	if err != nil {
		return func() {}, err
	}
	if getErr != nil { // it was new: askSecretNow's undo removes it
		return undo, nil
	}
	return func() { _ = vault.Set(sec, old) }, nil
}

// vpnAddSave stores a checked VPN v: its own vault secrets, then v.
func vpnAddSave(v *store.Vpn, secrets map[string]string, overwrite bool, check func(*store.State) error) error {
	if err := store.Update(check); err != nil {
		return err
	}
	for n, val := range secrets {
		if err := vault.Set(n, val); err != nil {
			return err
		}
	}
	return store.Update(func(s *store.State) error {
		if err := checkNewName(s, "vpn", v.Name, overwrite); err != nil {
			return err
		}
		s.Vpns[v.Name] = v
		return nil
	})
}

// readVpnCA reads an ikev2 VPN's --ca file (PEM); "" without one.
func readVpnCA(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(expandHome(path))
	if err != nil {
		return "", localFileErr("FILE_NOT_FOUND", err, "give the path of the CA certificate (PEM)")
	}
	if !strings.Contains(string(b), "-----BEGIN CERTIFICATE-----") {
		return "", out.Usage("--ca must be a PEM certificate file")
	}
	return string(b), nil
}

// vpnAddNotes are vpn add's notes on the VPN v it added from the file
// config; keysInFile: that file holds keys now kept in the vault.
func vpnAddNotes(v *store.Vpn, config string, keysInFile bool) []string {
	var notes []string
	if v.Kind == "wireguard" || v.Kind == "openvpn" && keysInFile {
		notes = append(notes, config+" still holds the keys that are now in the vault; delete it if you no longer need it")
	}
	if v.Check == "" {
		notes = append(notes, "without --check, `komando vpn up` and `komando test` cannot tell whether the VPN works; add one with `komando vpn edit "+v.Name+" --check HOST:PORT`")
	}
	if v.MFA {
		notes = append(notes, "a person logs in with `komando vpn up "+v.Name+"`; later commands reuse that session")
	}
	if k := netx.Kinds[v.Kind]; len(k.Client) > 0 {
		notes = append(notes, "needs "+strings.Join(k.Client, " and ")+" installed (`komando doctor` checks)")
	}
	return notes
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
