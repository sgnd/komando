package cli

import (
	"slices"
	"strings"
)

// The questions of the vpn commands, for every kind. A hint is made when a
// command asks for it (hintOf), from the one list below and the table, so
// nothing is built for the fourteen kinds at start.

// vpnFormLabels are the labels of the Add forms (vpnForms), by kind.
var vpnFormLabels = map[string]string{
	"globalprotect": "GlobalProtect", "fortinet": "FortiClient", "anyconnect": "Cisco AnyConnect",
	"pulse": "Pulse Secure or Ivanti", "f5": "F5 BIG-IP", "wireguard": "WireGuard", "openvpn": "OpenVPN or Pritunl",
	"tailscale": "Tailscale or Headscale", "l2tp": "L2TP/IPsec", "ipsec": "Cisco IPsec", "ikev2": "IKEv2",
	"system": "A VPN on this computer", "socks": "SOCKS proxy", "proxy": "HTTP proxy",
}

// hintOf is the hint of the command key, if it has one: the table of hints,
// or the one a vpn command gets (vpnHint).
func hintOf(key string) (formHint, bool) {
	if h, ok := formHints[key]; ok {
		return h, true
	}
	return vpnHint(key)
}

// vpnHint is the hint of `vpn KIND` and of `vpn KIND VERB`.
func vpnHint(key string) (formHint, bool) {
	w := strings.Fields(key)
	if len(w) < 2 || len(w) > 3 || w[0] != "vpn" || vpnFormLabels[w[1]] == "" {
		return formHint{}, false
	}
	kind := w[1]
	if len(w) == 2 {
		return formHint{}, true
	}
	cmd := "vpn " + kind + " "
	switch w[2] {
	case "add":
		return formHint{form: func(cl *call) []formGroup { return formKindOnly(cl, "VPN", vpnFormLabels[kind]) },
			next: []string{cmd + "start {}", cmd + "test {}", "host add NAME USER@ADDRESS --via {}"}}, true
	case "start":
		return formHint{args: []formArg{{ask: "Which VPN should connect?", pick: "vpn",
			help: "It stays up for later commands. When it asks for a login or a code, type it here."}},
			next: []string{cmd + "status", "test TARGET", cmd + "stop {}"}}, true
	case "stop":
		return formHint{args: []formArg{{ask: "Which VPN should disconnect?", pick: "vpn",
			help: "Pick one."}},
			next: []string{cmd + "status", cmd + "start {}"}}, true
	case "status":
		return formHint{args: []formArg{{ask: "Only one VPN? (leave empty for all)", pick: "vpn", free: true,
			help: "Pick one, or leave it empty."}}}, true
	case "list":
		return formHint{args: []formArg{{ask: "Only some VPNs? (leave empty for all)", pick: "vpn", free: true,
			help: "Pick one, or type @group or tag:office."}}}, true
	case "show":
		return formHint{args: []formArg{accVpn}}, true
	case "test":
		return formHint{args: []formArg{{ask: "Which VPN should be tested?", pick: "vpn",
			help: "komando connects through it and says whether it works."}},
			flags: []formFlag{{name: "wait", ask: "Keep trying for how long?", example: "5m",
				help: "Like 30s or 5m: it tests again every few seconds until it works. Leave empty to test once."}}}, true
	case "edit":
		return formHint{args: []formArg{accVpn}, flags: vpnEditFlagHints(kind)}, true
	case "rename":
		return formHint{args: []formArg{accVpn, accNewName}}, true
	case "remove":
		return formHint{args: []formArg{accVpns}}, true
	}
	return formHint{}, false
}

// vpnEditFlagHints are the flags vpn KIND edit asks about, those the kind has.
func vpnEditFlagHints(kind string) []formFlag {
	all := []formFlag{
		{name: "check", ask: "Which address can only be reached through this VPN?", example: "10.0.0.5:22",
			help: "An address and port inside the private network. komando connects to it to see that the VPN works. Leave empty to keep it."},
		{name: "user", ask: "New user name for the VPN login?", example: "alice",
			help: "Leave empty to keep it."},
		{name: "credential", ask: "Which credential holds the new password?", example: "office-pass",
			help: "Save it first as a credential (it asks hidden), then type its name here. Leave empty to keep it."},
		{name: "notes", ask: "Notes about this VPN?", example: "office in Jakarta, ask Budi for access",
			help: "Anything to remember. Leave empty to keep them."},
	}
	return slices.DeleteFunc(all, func(f formFlag) bool { return !vpnEditTakes(kind, f.name) })
}
