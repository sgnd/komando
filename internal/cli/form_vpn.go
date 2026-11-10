package cli

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/openvpn"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The VPN forms of Add, most common first. A secret the person types never
// goes on the command line: vpn add --ask-password asks the password
// hidden and keeps it as secret:NAME-pass, and vpn add --ask-psk asks a
// shared secret (pre-shared key, Cisco group password) hidden and keeps it
// as secret:NAME-psk. A Tailscale auth key is stored first with `komando
// secret set NAME-authkey`, which asks it hidden too. After the add comes
// `komando vpn up NAME` when a person has to log in, else `komando test
// NAME`.
func vpnForms() []formKind {
	return []formKind{
		{"WireGuard", "you have a file ending in .conf", wireguardForm},
		{"OpenVPN or Pritunl", "you have a file ending in .ovpn", openvpnForm},
		{"Tailscale or Headscale", "your team uses Tailscale", tailscaleForm},
		vpnPortalKind("globalprotect", "GlobalProtect", "Palo Alto; your company VPN app is GlobalProtect"),
		vpnPortalKind("fortinet", "FortiClient", "Fortinet SSL VPN; your company VPN app is FortiClient"),
		vpnPortalKind("anyconnect", "Cisco AnyConnect", "also Cisco Secure Client and ocserv"),
		vpnPortalKind("pulse", "Pulse Secure or Ivanti", "your company VPN app is Pulse Secure or Ivanti Secure Access"),
		vpnPortalKind("f5", "F5 BIG-IP", "your company VPN app is F5 Access or BIG-IP Edge Client"),
		{"L2TP/IPsec", "a server, a shared secret (PSK) and a user name", l2tpForm},
		{"Cisco IPsec", "an older Cisco VPN with a group name and a group password", ipsecForm},
		{"IKEv2", "a server with a shared secret, or a user name and password", ikev2Form},
		{"A VPN on this computer", "one already set up in your computer's network settings", systemVpnForm},
		{"SOCKS proxy", "one already running, like komando tunnel start HOST -D 1080", func() formSpec { return vpnProxyForm("socks") }},
		{"HTTP proxy", "your company's web proxy", func() formSpec { return vpnProxyForm("proxy") }},
	}
}

// Questions the VPN forms share.

// vpnNameQ asks the VPN's name. The vault secrets named after it (NAME
// plus each suffix) must be free: komando keeps its keys and passwords
// there.
func vpnNameQ(example string, suffixes ...string) formQ {
	q := formNameQ("vpn", "VPN", example)
	q.check = func(st *store.State, _ formAnswers, v string) string {
		if p := formNameProblem(st, "vpn", v); p != "" {
			return p
		}
		for _, sfx := range suffixes {
			if validName("secret", v+sfx) != nil {
				return "use a shorter name: komando keeps this VPN's secret as " + v + sfx
			}
			if users := secretUsers(st, v+sfx); len(users) > 0 {
				return "komando keeps this VPN's secret as " + v + sfx + ", which " + strings.Join(users, ", ") + " uses already; pick another name"
			}
		}
		return ""
	}
	return q
}

// vpnCheckQ asks for an address only the VPN reaches, so komando can tell
// whether it works.
func vpnCheckQ(required bool, example string) formQ {
	q := formQ{key: "check", label: "Test address", ask: "Which address can only be reached through this VPN?", example: example,
		help: "An address and port inside the private network, like a server's private IP and port 22. komando connects to it to see that the VPN works.",
		check: func(_ *store.State, _ formAnswers, v string) string {
			host, port, err := net.SplitHostPort(v)
			if p, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
				return "type an address and a port, like " + example
			}
			return ""
		}}
	if !required {
		q.optional = true
		q.help += " Enter skips it."
	}
	return q
}

// vpnServerQ asks an l2tp, ipsec or ikev2 VPN's server.
func vpnServerQ() formQ {
	return formQ{key: "server", label: "Server", ask: "What is the VPN server's address?", addr: true, example: "vpn.example.com",
		help: "A host name or IP address from your admin, or from the VPN settings on your phone or laptop.",
		check: func(_ *store.State, _ formAnswers, v string) string {
			if strings.Contains(v, "://") || strings.ContainsAny(v, "/ \t@") || strings.HasPrefix(v, "-") {
				return "type only the address, like vpn.example.com or 203.0.113.7, without https://"
			}
			return ""
		}}
}

// vpnUserQ asks the VPN login's user name.
func vpnUserQ(optional bool, help string) formQ {
	return formQ{key: "user", label: "User", ask: "What is your VPN user name?", optional: optional, example: "budi", help: help,
		check: func(_ *store.State, _ formAnswers, v string) string {
			if strings.ContainsAny(v, " \t") || strings.HasPrefix(v, "-") {
				return "a user name has no spaces and does not start with -"
			}
			return ""
		}}
}

// vpnPassQ asks how komando gets the VPN password: asked by the command,
// hidden, and kept in the vault (--ask-password); typed at each `vpn up`;
// or read from a password manager (--password-ref). def comes first. It is
// asked only once there is a user name.
func vpnPassQ(def string, canType bool) formQ {
	rows := map[string]menuRow{
		"save": {label: "Save it now, hidden", detail: "the command asks for it without showing it and keeps it in komando's vault", value: "save"},
		"type": {label: "Type it each time I connect", detail: "komando vpn up asks for it; best when you also need a code from your phone", value: "type"},
		"ref":  {label: "It is in a password manager", detail: "1Password, Bitwarden, KeePass, or an environment variable", value: "ref"},
	}
	order := []string{def}
	for _, k := range []string{"save", "type", "ref"} {
		if k != def && (k != "type" || canType) {
			order = append(order, k)
		}
	}
	return formQ{key: "pass", label: "Password", ask: "How should komando get your VPN password?",
		help: "The password is never shown and never written in the command.",
		def:  func(*store.State, formAnswers) string { return def },
		show: func(a formAnswers) bool { return a["user"] != "" },
		choices: func(*store.State, formAnswers) []menuRow {
			var rs []menuRow
			for _, k := range order {
				rs = append(rs, rows[k])
			}
			return rs
		}}
}

// vpnRefQ asks where a password manager keeps a secret, after the answer
// "ref" to the question from.
func vpnRefQ(key, from string) formQ {
	return formQ{key: key, label: "Kept in", ask: "Where is it kept?", example: "op://Work/VPN/password",
		help: "A reference, never the secret itself: op://vault/item/field (1Password), bw://item (Bitwarden), env:VPN_PASS (a variable).",
		show: func(a formAnswers) bool { return a[from] == "ref" },
		check: func(_ *store.State, _ formAnswers, v string) string {
			if !vault.ValidRef(v) {
				return "type a reference like op://Work/VPN/password or env:VPN_PASS, never the password itself"
			}
			return ""
		}}
}

// vpnPskQ asks how komando gets a shared secret (a pre-shared key, or a
// Cisco group password): typed hidden when vpn add --ask-psk asks, or
// from a password manager.
func vpnPskQ(label, what, help string) formQ {
	return formQ{key: "psk", label: label, ask: "How should komando get the " + what + "?", help: help,
		def: func(*store.State, formAnswers) string { return "save" },
		choices: func(*store.State, formAnswers) []menuRow {
			return []menuRow{{label: "Save it now, hidden", detail: "vpn add asks for it, hidden, and keeps it in komando's vault", value: "save"},
				{label: "It is in a password manager", detail: "1Password, Bitwarden, KeePass, or an environment variable", value: "ref"}}
		}}
}

// vpnMfaQ asks whether a login also needs a person: a code from a phone,
// or a browser sign-in. Not asked when the password is typed each time.
func vpnMfaQ() formQ {
	return formWhen(formYesNoQ("mfa", "Phone code", "Does logging in also need a code from your phone, or a sign-in in your browser?",
		"Then you connect it yourself with komando vpn up; later commands reuse that connection.", "no",
		"you connect it with komando vpn up", "komando connects it by itself"),
		func(a formAnswers) bool { return a["user"] != "" && a["pass"] != "type" })
}

// vpnLegacyQ is the More option for an old l2tp or ipsec server.
func vpnLegacyQ() formQ {
	return formMore(formYesNoQ("legacy", "Old encryption", "Is it an old server that needs old, weak encryption (3DES)?",
		"Only when connecting fails and your admin says the server is old. komando asks you to confirm it.", "no",
		"also allow 3DES and old key exchange", "modern encryption only"))
}

// Building the commands.

// vpnPassArgs adds how komando gets the login password.
func vpnPassArgs(args []string, a formAnswers) []string {
	switch {
	case a["user"] == "":
	case a["pass"] == "save":
		args = append(args, "--ask-password")
	case a["pass"] == "ref":
		args = append(args, "--password-ref", a["ref"])
	}
	return args
}

// vpnPskArgs adds --psk-ref for a key already stored, or --ask-psk: vpn
// add then asks for it hidden and keeps it as secret:NAME-psk.
func vpnPskArgs(args []string, a formAnswers) []string {
	if a["psk"] == "ref" {
		return append(args, "--psk-ref", a["pskref"])
	}
	return append(args, "--ask-psk")
}

// vpnBuild is the commands: the secrets typed first, vpn add, then vpn up
// when a person logs in, else a test.
func vpnBuild(a formAnswers, first [][]string, args []string, person bool) [][]string {
	if a["check"] != "" {
		args = append(args, "--check", a["check"])
	}
	next := []string{"test", a["name"]}
	if person {
		next = []string{"vpn", "up", a["name"]}
	}
	return append(first, formFlags(args, a), next)
}

// vpnMfa: the login also needs a code from a phone (asked only with a
// user name and a stored password).
func vpnMfa(a formAnswers) bool {
	return a["user"] != "" && a["pass"] != "type" && a["mfa"] == "yes"
}

// vpnPerson: a person logs in at vpn up (the password typed each time, or
// a code from a phone).
func vpnPerson(a formAnswers) bool {
	return a["user"] != "" && a["pass"] == "type" || vpnMfa(a)
}

// vpnFileText is a file's text, or "" when it cannot be read.
func vpnFileText(p string) string {
	b, err := os.ReadFile(expandHome(p))
	if err != nil {
		return ""
	}
	return string(b)
}

// WireGuard, OpenVPN, Tailscale.

func wireguardForm() formSpec {
	return formSpec{title: "Add a WireGuard VPN", qs: []formQ{
		vpnNameQ("office", "-key", "-psk"),
		{key: "config", label: "File", ask: "Where is the WireGuard file?", example: "~/Downloads/office.conf",
			help:  "The .conf file from your admin or the WireGuard app. komando moves its keys into its vault.",
			check: func(_ *store.State, _ formAnswers, v string) string { return wireguardFileProblem(v) }},
		vpnCheckQ(false, "10.0.0.5:22"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		return vpnBuild(a, nil, []string{"vpn", "add", a["name"], "wireguard", "--config", formAbs(a["config"])}, false)
	}}
}

// wireguardFileProblem checks the file is a WireGuard config.
func wireguardFileProblem(v string) string {
	if p := formFileProblem(v); p != "" {
		return p
	}
	text := vpnFileText(v)
	if strings.Contains(text, "\nremote ") || strings.HasSuffix(strings.ToLower(v), ".ovpn") {
		return "this is an OpenVPN file; Esc back to the list and pick OpenVPN"
	}
	if _, _, _, err := netx.StripWGKeys(text); err != nil {
		return "komando cannot read this as a WireGuard file: " + err.Error()
	}
	return ""
}

func openvpnForm() formSpec {
	needsUser := func(a formAnswers) bool { return ovpnNeedsUser(a["config"]) }
	return formSpec{title: "Add an OpenVPN VPN", qs: []formQ{
		vpnNameQ("office", "-config", "-pass"),
		{key: "config", label: "File", ask: "Where is the OpenVPN file?", example: "~/Downloads/office.ovpn",
			help:  "The .ovpn profile from your admin or Pritunl. komando keeps a copy in its vault.",
			check: func(_ *store.State, _ formAnswers, v string) string { return openvpnFileProblem(v) }},
		vpnCheckQ(true, "10.8.0.1:22"),
		formWhen(vpnUserQ(false, "This file logs in with a user name and password."), needsUser),
		formWhen(vpnPassQ("save", true), needsUser),
		formWhen(vpnRefQ("ref", "pass"), needsUser),
		formWhen(vpnMfaQ(), needsUser),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := []string{"vpn", "add", a["name"], "openvpn", "--config", formAbs(a["config"])}
		person := false
		if ovpnNeedsUser(a["config"]) && a["user"] != "" {
			args = vpnPassArgs(append(args, "--user", a["user"]), a)
			if person = vpnPerson(a); person {
				args = append(args, "--mfa")
			}
		}
		return vpnBuild(a, nil, args, person)
	}}
}

// openvpnFileProblem checks the file is a profile komando's own client
// takes.
func openvpnFileProblem(v string) string {
	if p := formFileProblem(v); p != "" {
		return p
	}
	text := vpnFileText(v)
	if strings.Contains(text, "[Interface]") {
		return "this is a WireGuard file; Esc back to the list and pick WireGuard"
	}
	if _, err := ovpnRemotes(text); err != nil {
		return "komando cannot use this file (" + err.Error() + "); ask your admin for a profile with everything inside it"
	}
	if _, err := openvpn.Parse(text); err != nil {
		return "komando cannot use this file: " + err.Error()
	}
	return ""
}

// ovpnNeedsUser: the profile logs in with a user name and password.
func ovpnNeedsUser(path string) bool {
	if path == "" {
		return false
	}
	p, err := openvpn.Parse(vpnFileText(path))
	return err == nil && p.AuthUserPass
}

func tailscaleForm() formSpec {
	return formSpec{title: "Add Tailscale", qs: []formQ{
		vpnNameQ("tailnet", "-authkey"),
		{key: "login", label: "Login", ask: "How do you want to log in?",
			help: "An auth key is made on the Tailscale admin page, under Settings, Keys. It starts with tskey-.",
			def:  func(*store.State, formAnswers) string { return "browser" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "Sign in with my browser", detail: "komando vpn up shows a link; you sign in as in the Tailscale app", value: "browser"},
					{label: "An auth key", detail: "komando secret set asks for it next, hidden; then komando connects by itself", value: "authkey"}}
			}},
		vpnCheckQ(false, "100.64.0.5:22"),
		formMore(formQ{key: "server", label: "Headscale", ask: "Do you use your own Headscale server? Its address:", optional: true,
			example: "https://headscale.example.com", help: "Only for Headscale. Empty for the normal Tailscale.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") || strings.Contains(v, "@") {
					return "type the full address, like https://headscale.example.com"
				}
				return ""
			}}),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := []string{"vpn", "add", a["name"], "tailscale"}
		if a["server"] != "" {
			args = append(args, "--server", a["server"])
		}
		if a["login"] != "authkey" {
			return vpnBuild(a, nil, args, true)
		}
		sec := a["name"] + "-authkey"
		return vpnBuild(a, [][]string{{"secret", "set", sec}}, append(args, "--password-ref", "secret:"+sec), false)
	}}
}

// Company VPN apps: a portal.

// vpnPortalKind is a company SSL VPN: GlobalProtect, FortiClient and the
// others take the same questions.
func vpnPortalKind(kind, product, detail string) formKind {
	if c := netx.Kinds[kind].Client; len(c) > 0 {
		detail += "; needs the " + strings.Join(c, " and ") + " programs"
	}
	return formKind{label: product, detail: detail, spec: func() formSpec { return vpnPortalForm(kind, product) }}
}

func vpnPortalForm(kind, product string) formSpec {
	where := map[string]string{
		"globalprotect": "The Portal address in the GlobalProtect app.",
		"fortinet":      "The Remote Gateway in FortiClient. Add :port when FortiClient shows one, like :10443.",
		"anyconnect":    "The address in the AnyConnect connect box, sometimes with /group at the end.",
		"pulse":         "The server URL in the Pulse Secure or Ivanti app.",
		"f5":            "The server address in the F5 Access app, or the page you sign in on.",
	}[kind]
	return formSpec{title: "Add a " + product + " VPN", qs: []formQ{
		vpnNameQ("client-x", "-pass"),
		{key: "portal", label: "Address", ask: "What is the VPN's address?", addr: true, example: "vpn.example.com",
			help: where + " Your company's IT team knows it too.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.ContainsAny(v, " \t") || strings.HasPrefix(v, "-") {
					return "type only the address, like vpn.example.com or https://vpn.example.com"
				}
				return ""
			}},
		vpnUserQ(true, "Usually your work login. Empty to type it each time you connect."),
		vpnPassQ("type", true), vpnRefQ("ref", "pass"), vpnMfaQ(),
		vpnCheckQ(false, "10.0.0.5:22"),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := []string{"vpn", "add", a["name"], kind, "--portal", a["portal"]}
		if a["user"] != "" {
			args = vpnPassArgs(append(args, "--user", a["user"]), a)
		}
		if vpnMfa(a) {
			args = append(args, "--mfa")
		}
		return vpnBuild(a, nil, args, a["user"] == "" || vpnPerson(a))
	}}
}

// IPsec: L2TP, Cisco IPsec, IKEv2.

func l2tpForm() formSpec {
	return formSpec{title: "Add an L2TP/IPsec VPN", qs: []formQ{
		vpnNameQ("office", "-psk", "-pass"),
		vpnServerQ(),
		vpnPskQ("Shared secret", "shared secret (pre-shared key)", "One password for the whole office, often called IPsec secret or PSK. Your admin gives it to you."),
		vpnRefQ("pskref", "psk"),
		vpnUserQ(false, "Your own login on the VPN, from your admin."),
		vpnPassQ("save", true), vpnRefQ("ref", "pass"),
		vpnCheckQ(false, "10.0.0.5:22"),
		vpnLegacyQ(),
		formMore(formYesNoQ("pap", "Plain login", "Does the old server only take a plain (PAP) login?",
			"PAP hands the server your password itself. Only when your admin says so; komando asks you to confirm it.", "no",
			"allow a PAP login", "only safer logins")),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := vpnPskArgs([]string{"vpn", "add", a["name"], "l2tp", "--server", a["server"]}, a)
		args = vpnPassArgs(append(args, "--user", a["user"]), a)
		if a["legacy"] == "yes" {
			args = append(args, "--legacy-crypto")
		}
		if a["pap"] == "yes" {
			args = append(args, "--allow-pap")
		}
		return vpnBuild(a, nil, args, vpnPerson(a))
	}}
}

func ipsecForm() formSpec {
	return formSpec{title: "Add a Cisco IPsec VPN", qs: []formQ{
		vpnNameQ("office", "-psk", "-pass"),
		vpnServerQ(),
		{key: "id", label: "Group", ask: "What is the group name?", optional: true, example: "staff",
			help: "In the Cisco VPN settings it is called Group or Group name. Empty if you have none."},
		vpnPskQ("Group password", "group password", "The password that belongs to the group name, not your own. Your admin gives it to you."),
		vpnRefQ("pskref", "psk"),
		vpnUserQ(true, "Your own login on the VPN. Empty if it has none."),
		vpnPassQ("save", true), vpnRefQ("ref", "pass"),
		vpnCheckQ(false, "10.0.0.5:22"),
		vpnLegacyQ(),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := vpnPskArgs([]string{"vpn", "add", a["name"], "ipsec", "--server", a["server"]}, a)
		if a["id"] != "" {
			args = append(args, "--id", a["id"])
		}
		if a["user"] != "" {
			args = vpnPassArgs(append(args, "--user", a["user"]), a)
		}
		if a["legacy"] == "yes" {
			args = append(args, "--legacy-crypto")
		}
		return vpnBuild(a, nil, args, vpnPerson(a))
	}}
}

func ikev2Form() formSpec {
	byUser := func(a formAnswers) bool { return a["auth"] != "psk" }
	byPsk := func(a formAnswers) bool { return a["auth"] == "psk" }
	return formSpec{title: "Add an IKEv2 VPN", qs: []formQ{
		vpnNameQ("office", "-psk", "-pass"),
		vpnServerQ(),
		{key: "auth", label: "Login", ask: "How do you log in?",
			def: func(*store.State, formAnswers) string { return "user" },
			choices: func(*store.State, formAnswers) []menuRow {
				return []menuRow{{label: "A user name and password", detail: "the server proves itself with a certificate", value: "user"},
					{label: "A shared secret", detail: "one pre-shared key (PSK) for everyone", value: "psk"}}
			}},
		formWhen(vpnPskQ("Shared secret", "shared secret (pre-shared key)", "Your admin gives it to you; it is often called PSK."), byPsk),
		vpnRefQ("pskref", "psk"),
		formWhen(vpnUserQ(false, "Your own login on the VPN."), byUser),
		formWhen(vpnPassQ("save", true), byUser), formWhen(vpnRefQ("ref", "pass"), byUser),
		vpnCheckQ(false, "10.0.0.5:22"),
		formMore(formQ{key: "ca", label: "Certificate", ask: "Did your admin give you the server's certificate file?", optional: true,
			example: "~/Downloads/vpn-ca.pem", help: "A .pem or .crt file. Empty when the server has a normal public certificate.",
			check: func(_ *store.State, _ formAnswers, v string) string {
				if p := formFileProblem(v); p != "" {
					return p
				}
				if !strings.Contains(vpnFileText(v), "-----BEGIN CERTIFICATE-----") {
					return "this is not a certificate file (it has no BEGIN CERTIFICATE line)"
				}
				return ""
			}}),
		formMore(formQ{key: "id", label: "Your identity", ask: "Does the server know you by another name than your user name?", optional: true,
			example: "budi@example.com", help: "Only when your admin gives you an identity. Empty uses your user name."}),
		formMore(formQ{key: "remoteid", label: "Server identity", ask: "Does the server have another name than its address?", optional: true,
			example: "vpn.example.com", help: "Only when your admin gives you one. Empty uses the server address."}),
		formGroupQ(), formNotesQ(),
	}, build: ikev2Build}
}

func ikev2Build(_ *store.State, a formAnswers) [][]string {
	args := []string{"vpn", "add", a["name"], "ikev2", "--server", a["server"]}
	var first [][]string
	if a["auth"] == "psk" {
		args = vpnPskArgs(args, a)
		a = formAnswers{"name": a["name"], "check": a["check"], "ca": a["ca"], "id": a["id"], "remoteid": a["remoteid"],
			"group": a["group"], "notes": a["notes"]} // a user typed before is not used
	} else {
		args = vpnPassArgs(append(args, "--user", a["user"]), a)
	}
	for _, f := range [][2]string{{"ca", "--ca"}, {"id", "--id"}, {"remoteid", "--remote-id"}} {
		if a[f[0]] != "" {
			v := a[f[0]]
			if f[0] == "ca" {
				v = formAbs(v)
			}
			args = append(args, f[1], v)
		}
	}
	return vpnBuild(a, first, args, vpnPerson(a))
}

// VPNs komando does not run itself.

func systemVpnForm() formSpec {
	return formSpec{title: "Add a VPN on this computer", qs: []formQ{
		vpnNameQ("corp"),
		vpnCheckQ(true, "10.20.0.1:443"),
		{key: "service", label: "Name in settings", ask: "What is the VPN called in your computer's network settings?", optional: true,
			example: "Corp VPN", help: "On a Mac: System Settings, VPN. With it, komando vpn up can switch it on. Enter skips it: then you switch it on yourself."},
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := []string{"vpn", "add", a["name"], "system"}
		if a["service"] != "" {
			args = append(args, "--service", a["service"])
		}
		return vpnBuild(a, nil, args, false)
	}}
}

// vpnProxyForm is a SOCKS proxy or a company HTTP proxy. Its login is a
// More option: most need none.
func vpnProxyForm(kind string) formSpec {
	title, example, help := "Add a SOCKS proxy", "127.0.0.1:1080", "Its address and port. For komando tunnel start web1 -D 1080 it is 127.0.0.1:1080."
	if kind == "proxy" {
		title, example, help = "Add an HTTP proxy", "proxy.example.com:3128", "Its address and port, from your browser's proxy settings or your IT team."
	}
	return formSpec{title: title, qs: []formQ{
		vpnNameQ("lab", "-pass"),
		{key: "address", label: "Address", ask: "What is the proxy's address?", addr: true, example: example, help: help,
			check: func(_ *store.State, _ formAnswers, v string) string {
				if strings.Contains(v, "@") {
					return "type only the address; a user name goes under More options"
				}
				if _, err := vpnAddress(kind, v); err != nil {
					return "type an address and a port, like " + example
				}
				return ""
			}},
		formMore(vpnUserQ(true, "Only when the proxy asks for a login. Empty for none.")),
		formMore(vpnPassQ("save", false)), formMore(vpnRefQ("ref", "pass")),
		formGroupQ(), formNotesQ(),
	}, build: func(_ *store.State, a formAnswers) [][]string {
		args := []string{"vpn", "add", a["name"], kind, "--address", a["address"]}
		if a["user"] != "" {
			args = vpnPassArgs(append(args, "--user", a["user"]), a)
		}
		return vpnBuild(a, nil, args, false)
	}}
}
