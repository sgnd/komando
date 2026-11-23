package capability

// vpn: the networks komando reaches targets through. up and down become
// start and stop.

var mfaOpt = Option{Name: "mfa", Kind: Bool, Help: "a person answers the second factor at each connect"}

// pskOpt is WireGuard's post-quantum layer: komando makes the preshared
// key at 256 bits and keeps it as a credential; nobody types it.
var pskOpt = Option{Name: "psk-credential", Kind: Credential, Generated: true,
	Help: "the credential holding the preshared key komando makes"}

var vpnProviders = vpnProviderList()

func vpnProviderList() []provider {
	var ps []provider
	for _, name := range []string{"wireguard", "openvpn", "globalprotect", "fortinet", "anyconnect", "pulse",
		"f5", "l2tp", "ipsec", "ikev2", "tailscale", "system", "socks", "proxy"} {
		p := provider{name: name, connect: []Option{credentialOpt}}
		if name == "wireguard" {
			p.connect = append(p.connect, pskOpt)
		}
		ps = append(ps, p)
	}
	return ps
}

var vpnInventory = inventory{
	typ: "vpn",
	today: ids{"add": {"vpn.add"}, "edit": {"vpn.edit"}, "list": {"vpn.list"}, "remove": {"vpn.rm"},
		"rename": {"vpn.rename"}, "show": {"vpn.show"}, "test": {"vpn.test"}},
	guard: "guardProtection",
	edit:  []Option{mfaOpt},
}

var vpnLeaves = each(vpnProviders, func(p provider) []Leaf {
	key := func(verb string) Key { return Key{Type: "vpn", Provider: p.name, Verb: verb} }
	return append(vpnInventory.leaves(p),
		Leaf{Key: key("start"), Args: oneName, Today: []string{"vpn.up"}},
		Leaf{Key: key("stop"), Args: oneName, Today: []string{"vpn.down"}},
		Leaf{Key: key("status"), Args: []Arg{{Name: "NAME", Optional: true}}, LocalRead: true, Today: []string{"vpn.status"}},
	)
})
