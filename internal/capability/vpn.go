package capability

import (
	"slices"
	"strings"
)

// vpn: the networks komando reaches targets through. A VPN is saved under
// a name and used by putting that name first in a --via path; up and down
// become start and stop. Every provider sits under its own word
// (vpn wireguard add), and what it takes is its own: a portal, a config
// file, a server and a key, a proxy address.

var mfaOpt = Option{Name: "mfa", Kind: Bool, Help: "a person answers the second factor at each connect"}

// pskOpt is WireGuard's post-quantum layer: komando makes the preshared
// key at 256 bits and keeps it as a credential; nobody types it.
var pskOpt = Option{Name: "psk-credential", Kind: Credential, Generated: true,
	Help: "the credential holding the preshared key komando makes"}

// The options the kinds pick from. A kind lists the ones it needs, the
// ones it needs one of (the command checks which), and the ones it takes.
var (
	vpnConfigOpt  = Option{Name: "config", Kind: File, Help: "the config file; its keys go into the vault"}
	vpnCheckOpt   = Option{Name: "check", Kind: String, Help: "host:port reachable only through this VPN (start and test connect to it)"}
	vpnUserOpt    = Option{Name: "user", Kind: String, Help: "user name for the VPN login"}
	vpnPortalOpt  = Option{Name: "portal", Kind: String, Help: "the VPN server or portal"}
	vpnServerOpt  = Option{Name: "server", Kind: String, Help: "the VPN server (host or host:port)"}
	vpnProxyOpt   = Option{Name: "proxy-address", Kind: String, Help: "host:port of the proxy; an HTTP proxy also takes http(s)://host:port"}
	vpnServiceOpt = Option{Name: "service", Kind: String, Help: "its name in your computer's settings, so start can connect it"}
	vpnIDOpt      = Option{Name: "id", Kind: String, Help: "the group name (IPsec) or your identity (IKEv2; default: --user)"}
	vpnRemoteOpt  = Option{Name: "remote-id", Kind: String, Help: "the server's identity, if not its --server name"}
	vpnCAOpt      = Option{Name: "ca", Kind: File, Help: "the CA certificate (PEM) that signed the server's certificate, if not a public one"}
	vpnPassOpt    = Option{Name: "credential", Kind: Credential, Help: "the credential holding the login password"}
	vpnKeyOpt     = Option{Name: "credential", Kind: Credential, Help: "the credential holding the auth key"}
	vpnPSKRefOpt  = Option{Name: "psk-credential", Kind: Credential, Help: "the credential holding the pre-shared key (IPsec: the group password)"}
	vpnAskPSKOpt  = Option{Name: "ask-psk", Kind: Bool, Help: "type the pre-shared key now (hidden, a person at a terminal); it is stored as a credential"}
	vpnLegacyOpt  = Option{Name: "legacy-crypto", Kind: Bool, Help: "also offer 3DES and DH groups 2 and 5, for old servers (weak; needs a person's yes)"}
	vpnPAPOpt     = Option{Name: "allow-pap", Kind: Bool, Help: "let the server pick a login that does not prove it is the server: PAP, CHAP-MD5 or none (needs a person's yes)"}
)

// vpnKind is one provider of vpn.
type vpnKind struct {
	provider
	title string   // what people call it: "WireGuard"
	noun  string   // what komando saves of it: "VPN" (default), "proxy", "profile"
	an    bool     // "an OpenVPN profile"
	need  []Option // given every time
	oneOf []Option // at least one of these, which the command checks
	takes []Option // given when they apply
	add   string   // the flags of the add example
	group string   // the text of the group
}

func required(o Option) Option { o.Required = true; return o }

var vpnKinds = []vpnKind{
	{provider: provider{name: "wireguard"}, title: "WireGuard", group: "WireGuard: save a VPN, connect it and check it",
		need: []Option{required(vpnConfigOpt)}, takes: []Option{pskOpt},
		add: "--config ~/Downloads/office.conf --check 10.0.0.5:22"},
	{provider: provider{name: "openvpn"}, title: "OpenVPN", noun: "profile", an: true, group: "OpenVPN: save a VPN, connect it and check it",
		need: []Option{required(vpnConfigOpt), required(vpnCheckOpt)}, takes: []Option{vpnUserOpt, vpnPassOpt, askPassOpt},
		add: "--config office.ovpn --check 10.8.0.1:22 --user alice --credential office-pass"},
	portalKind("globalprotect", "GlobalProtect", false),
	portalKind("fortinet", "Fortinet", false),
	portalKind("anyconnect", "Cisco AnyConnect", false),
	portalKind("pulse", "Pulse Secure or Ivanti", false),
	portalKind("f5", "F5 BIG-IP", true),
	{provider: provider{name: "l2tp"}, title: "L2TP/IPsec", an: true, group: "L2TP/IPsec: save a VPN, connect it and check it",
		need: []Option{required(vpnServerOpt), required(vpnUserOpt)}, oneOf: []Option{vpnPSKRefOpt, vpnAskPSKOpt},
		takes: []Option{vpnPassOpt, askPassOpt, vpnLegacyOpt, vpnPAPOpt},
		add:   "--server vpn.example.com --psk-credential office-psk --user alice"},
	{provider: provider{name: "ipsec"}, title: "Cisco IPsec", group: "Cisco IPsec: save a VPN, connect it and check it",
		need: []Option{required(vpnServerOpt)}, oneOf: []Option{vpnPSKRefOpt, vpnAskPSKOpt},
		takes: []Option{vpnIDOpt, vpnUserOpt, vpnPassOpt, askPassOpt, vpnLegacyOpt},
		add:   "--server asa.client.com --id staff --psk-credential office-psk --user alice"},
	{provider: provider{name: "ikev2"}, title: "IKEv2", an: true, group: "IKEv2: save a VPN, connect it and check it",
		need: []Option{required(vpnServerOpt)}, oneOf: []Option{vpnPSKRefOpt, vpnAskPSKOpt, vpnUserOpt},
		takes: []Option{vpnPassOpt, askPassOpt, vpnIDOpt, vpnRemoteOpt, vpnCAOpt},
		add:   "--server vpn.example.com --user alice --credential office-pass"},
	{provider: provider{name: "tailscale"}, title: "Tailscale", group: "Tailscale: save a tailnet, connect it and check it",
		takes: []Option{vpnKeyOpt, vpnServerOpt},
		add:   "--credential office-authkey"},
	{provider: provider{name: "system"}, title: "system", group: "System VPN: save one your computer has, connect it and check it",
		need: []Option{required(vpnCheckOpt)}, takes: []Option{vpnServiceOpt},
		add: `--service "Corp VPN" --check 10.20.0.1:443`},
	{provider: provider{name: "socks"}, title: "SOCKS", noun: "proxy", group: "SOCKS proxy: save one that runs already and check it",
		need: []Option{required(vpnProxyOpt)}, takes: []Option{vpnUserOpt, vpnPassOpt, askPassOpt},
		add: "--proxy-address 127.0.0.1:1080"},
	{provider: provider{name: "proxy"}, title: "HTTP", noun: "proxy", an: true, group: "HTTP proxy: save a company proxy and check it",
		need: []Option{required(vpnProxyOpt)}, takes: []Option{vpnUserOpt, vpnPassOpt, askPassOpt},
		add: "--proxy-address proxy.corp.example:3128"},
}

// portalKind is a corporate SSL VPN: one portal address and a login.
func portalKind(name, title string, an bool) vpnKind {
	return vpnKind{provider: provider{name: name}, title: title, an: an, group: title + ": save a VPN, connect it and check it",
		need: []Option{required(vpnPortalOpt)}, takes: []Option{vpnUserOpt, vpnPassOpt, askPassOpt},
		add: "--portal vpn.client.com --user alice"}
}

// VpnGroupShort is the text of the group of a provider (vpn wireguard).
func VpnGroupShort(provider string) string {
	for _, k := range vpnKinds {
		if k.name == provider {
			return k.group
		}
	}
	return ""
}

var vpnInventory = inventory{
	typ: "vpn",
	today: ids{"add": {"vpn.add"}, "edit": {"vpn.edit"}, "list": {"vpn.list"}, "remove": {"vpn.rm"},
		"rename": {"vpn.rename"}, "show": {"vpn.show"}, "test": {"vpn.test"}},
	guard: "guardProtection",
	edit:  []Option{mfaOpt},
}

var vpnLeaves = vpnTable()

func vpnTable() []Leaf {
	var out []Leaf
	for _, k := range vpnKinds {
		key := func(verb string) Key { return Key{Type: "vpn", Provider: k.name, Verb: verb} }
		// the stops of add and edit are those of a leaf that names a credential
		base := vpnInventory.leaves(provider{name: k.name, connect: []Option{credentialOpt}})
		for _, l := range base {
			completeVpn(&l, k)
			out = append(out, l)
		}
		for _, verb := range []string{"start", "stop", "status"} {
			l := Leaf{Key: key(verb), Args: oneName}
			switch verb {
			case "start":
				l.Today = []string{"vpn.up"}
			case "stop":
				l.Today = []string{"vpn.down"}
			default:
				l.Args, l.LocalRead, l.Today = []Arg{{Name: "NAME", Optional: true}}, true, []string{"vpn.status"}
			}
			completeVpn(&l, k)
			out = append(out, l)
		}
	}
	return out
}

// addOptions are the options of vpn PROVIDER add: what the provider needs
// and takes, then what every VPN takes.
func (k vpnKind) addOptions() []Option {
	var o []Option
	o = append(o, k.need...)
	o = append(o, k.oneOf...)
	for _, t := range k.takes {
		if !hasOption(o, t.Name) {
			o = append(o, t)
		}
	}
	if !hasOption(o, "check") {
		o = append(o, vpnCheckOpt)
	}
	return append(o, mfaOpt, protectedOpt, labelOpt, groupOpt, tagOpt, notesOpt, overwriteOp)
}

// editOptions are the options of vpn PROVIDER edit: the settings of add
// that can change after it (not the config file, not the ones that type a
// secret now), and the common ones.
func (k vpnKind) editOptions() []Option {
	var o, unset []Option
	for _, a := range k.addOptions() {
		switch a.Name {
		case "config", "ask-password", "ask-psk", "overwrite", "mfa", "protected", "label", "group", "tag", "notes":
			continue
		}
		a.Required = false // an edit gives only what changes
		o = append(o, a)
	}
	unset = append(unset, vpnCheckOpt)
	for _, a := range o {
		if !a.Generated && slices.Contains([]string{"user", "credential", "psk-credential", "id", "remote-id", "ca"}, a.Name) {
			unset = append(unset, a)
		}
	}
	words := []string{}
	for _, u := range unset {
		words = append(words, u.Name)
	}
	words = append(words, "notes")
	o = append(o, mfaOpt, protectedOpt, labelOpt, notesOpt)
	o = append(o, optionByName(connEditOptions, "add-group"), optionByName(connEditOptions, "rm-group"),
		optionByName(connEditOptions, "add-tag"), optionByName(connEditOptions, "rm-tag"),
		Option{Name: "unset", Kind: String, Repeat: true, List: true, Help: "clear these settings: " + strings.Join(words, ", ")})
	return o
}

func hasOption(os []Option, name string) bool {
	for _, o := range os {
		if o.Name == name {
			return true
		}
	}
	return false
}

func optionByName(os []Option, name string) Option {
	for _, o := range os {
		if o.Name == name {
			return o
		}
	}
	panic("capability: no option " + name)
}

// one is how a Short names one VPN of the provider: "a WireGuard VPN".
func (k vpnKind) one() string {
	article := "a "
	if k.an {
		article = "an "
	}
	return article + k.title + " " + cmpOr(k.noun, "VPN")
}

// many is the same for several: "WireGuard VPNs".
func (k vpnKind) many() string {
	switch noun := cmpOr(k.noun, "VPN"); noun {
	case "proxy":
		return k.title + " proxies"
	default:
		return k.title + " " + noun + "s"
	}
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// completeVpn gives a vpn leaf the arguments, options and texts of the
// command of today it keeps.
func completeVpn(l *Leaf, k vpnKind) {
	cmd := "  komando vpn " + k.name + " "
	lines := func(l ...string) string { return strings.Join(l, "\n") }
	switch l.Verb {
	case "add":
		l.Options = k.addOptions()
		l.Short = "Save " + k.one() + " under a short name"
		l.Example = lines(cmd+"add office "+k.add, cmd+"add office "+k.add+" --dry-run")
	case "edit":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Many: true}}
		l.Options = k.editOptions()
		l.Short = "Change saved " + k.many() + " (only the flags you give)"
		l.Example = lines(cmd+"edit office --check 10.0.0.5:22", cmd+"edit @office --protected --dry-run")
	case "list":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Optional: true}}
		l.Options = []Option{limitOpt}
		l.Short = "List the saved " + k.many()
		l.Example = lines(cmd+"list", cmd+"list @office")
	case "show":
		l.Short = "Show a saved " + k.title + " " + cmpOr(k.noun, "VPN") + " (saved keys are never shown)"
		l.Example = lines(cmd+"show office", cmd+"show office -o json")
	case "rename":
		l.Short = "Rename a saved " + k.title + " " + cmpOr(k.noun, "VPN") + " and every reference to it"
		l.Example = lines(cmd+"rename office office-2 --dry-run", cmd+"rename office office-2")
	case "remove":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Many: true}}
		l.Short = "Forget saved " + k.many() + " (the network is not touched)"
		l.Example = lines(cmd+"remove office --dry-run", cmd+"remove office")
	case "test":
		l.Args = []Arg{{Name: "TARGET", Selector: true}}
		l.Options = []Option{endOpt, waitOpt}
		l.Short = "Check that a saved " + k.title + " " + cmpOr(k.noun, "VPN") + " connects"
		l.Example = lines(cmd+"test office", cmd+"test @office --wait 5m")
	case "start":
		l.Short = "Connect " + k.one() + " now and keep it up"
		l.Example = lines(cmd+"start office --dry-run", cmd+"start office")
	case "stop":
		l.Short = "Disconnect " + k.one() + " that is up"
		l.Example = lines(cmd+"stop office --dry-run", cmd+"stop office")
	case "status":
		l.Short = "Show whether a " + k.title + " " + cmpOr(k.noun, "VPN") + " is connected and what uses it"
		l.Example = lines(cmd+"status", cmd+"status office -o json")
	}
}
