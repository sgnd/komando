package cli

import (
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// The questions for the VPNs, logins and tunnels area and the Secrets and
// keys area. vpn add has a hand-made form (form_vpn.go).

// Answers several hints share.
var (
	accVpn = formArg{ask: "Which VPN?", pick: "vpn",
		help: "One from your list. `komando list` shows them."}
	accVpns = formArg{ask: "Which VPNs?", pick: "vpn",
		help: "Pick one, or type several names separated by spaces."}
	accNewName = formArg{ask: "What should the new name be?", example: "office-jkt",
		help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}
	accSecret = formArg{ask: "Which secret?", example: "db-pass", pick: "secret", free: true,
		help: "The name you saved it under. komando credential list shows your saved passwords."}
	accSecretAdd = formArg{ask: "What name should it have?", example: "db-pass", pick: "secret", free: true,
		help: "Pick one to give it a new value, or type a new name: letters, digits, dot, dash and underscore, starting with a letter or digit. komando asks for the value next and hides it as you type or paste."}
	accSecrets = formArg{ask: "Which ones?", example: "old-pass", pick: "secret", free: true,
		help: "Their names. Several: separate them with spaces. One still in use is not deleted."}
	accSecretNew = formArg{ask: "What should the new name be?", example: "db-pass-old",
		help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}
	accOverwrite = formFlag{name: "overwrite", ask: "Replace the new name if it exists already?",
		help: "No stops when a secret with the new name is there, so nothing is lost by mistake."}
	accKey = formArg{ask: "Which key?", pick: "key",
		help: "One of your komando SSH keys. `komando credential key list` shows them."}
	accKeyOrPub = formArg{ask: "Which key?", pick: "key", free: true, local: true, example: "~/.ssh/id_ed25519.pub",
		help: "One of your komando SSH keys, or type the path of a .pub file on this computer."}
	accServers = formArg{ask: "On which servers?", pick: "host", free: true,
		help: "Pick one from your list, or type @group, tag:prod or several names separated by spaces or commas."}
	accPassRef = formFlag{name: "passphrase-credential", ask: "Which saved password opens the key?", example: "work-key-pass",
		help: "Only for a key that has a passphrase. Save it first with `komando credential password add NAME` (it asks hidden), then type its NAME here. Leave empty for a key without one."}
	accSecretOff = formFlag{name: "off", ask: "Move the key back into the store.key file instead?",
		help: "No is the usual answer. Yes makes a copy of ~/.komando open the vault again, so komando asks you to confirm first."}
)

func init() {
	addFormHints(map[string]formHint{
		// Tunnels
		"host ssh tunnel start": {area: "VPNs, logins and tunnels", args: []formArg{{ask: "To which server or conn?", pick: "target", free: true,
			help: "Pick a conn (a database, a cache) to reach it from this computer, or a server to forward a port through it."}},
			flags: []formFlag{
				{name: "port", ask: "Which port on this computer? (for a conn)", example: "15432",
					help: "Point your app at localhost and this port. Leave empty for a free one; komando shows which."},
				{name: "local", ask: "What should it forward? (for a server)", example: "8080:localhost:80",
					help: "LOCALPORT:ADDRESS:PORT: localhost:8080 here reaches localhost:80 as the server sees it. Leave empty for a conn."},
			}},
		"host ssh tunnel list": {area: "VPNs, logins and tunnels"},
		"host ssh tunnel stop": {area: "VPNs, logins and tunnels", args: []formArg{{ask: "Which tunnels should stop? (leave empty with --all)", pick: "tunnel", free: true,
			help: "Their IDs: `komando host ssh tunnel list` shows them. Several: separate them with spaces."}},
			flags: []formFlag{{name: "all", ask: "Stop every tunnel instead?"}}},

		// Logins
		"login": {form: loginForm},
		"login aws": {flags: []formFlag{{name: "profile", ask: "Which AWS profile?", example: "prod",
			help: "Its name in ~/.aws/config. Leave empty for the usual one. Your browser opens for the AWS sign-in."}}},
		"logout aws": {flags: []formFlag{{name: "profile", ask: "Which AWS profile?", example: "prod",
			help: "The profile in ~/.aws/config whose SSO login should end. Empty: AWS_PROFILE, else default."}}},
		"logout": {args: []formArg{{ask: "From which servers? (leave empty with --all)", pick: "host", free: true,
			help: "Ends the login `komando login` kept. Several: separate them with spaces."}},
			flags: []formFlag{{name: "all", ask: "End every kept login instead?"}}},

		// Secrets
		"credential password add":  {args: []formArg{accSecretAdd}},
		"credential token add":     {args: []formArg{accSecretAdd}},
		"credential password show": {args: []formArg{accSecret}},
		"credential token show":    {args: []formArg{accSecret}},
		"secret check": {args: []formArg{{ask: "Which secret should your value be compared with?", example: "vpn-pass", pick: "secret", free: true,
			help: "Its name in the vault. komando asks for your value next, hidden, and says whether it matches, never showing either."}}},
		"credential list":            {},
		"credential password rename": {args: []formArg{accSecret, accSecretNew}, flags: []formFlag{accOverwrite}},
		"credential token rename":    {args: []formArg{accSecret, accSecretNew}, flags: []formFlag{accOverwrite}},
		"secret cp":                  {args: []formArg{accSecret, accSecretNew}, flags: []formFlag{accOverwrite}},
		"credential password remove": {args: []formArg{accSecrets}},
		"credential token remove":    {args: []formArg{accSecrets}},
		"credential run": {args: []formArg{{ask: "Which program should run on this computer?", example: "terraform plan",
			help: "The program and its arguments, as you would type them here. Its secrets go in the next question, never here."}},
			flags: []formFlag{{name: "env", ask: "Which variable gets which secret?", example: "TOKEN=credential:gh-token",
				help: "KEY=credential:NAME reads NAME from the vault right before the program starts. KEY=VALUE sets a plain value."}}},
		"config vault keychain": {flags: []formFlag{accSecretOff}},
		"config vault passphrase": {flags: []formFlag{{name: "off", ask: "Go back to a random key in store.key instead?",
			help: "No is the usual answer: komando asks for the new passphrase twice, hidden. Yes asks you to confirm first."}}},

		// SSH keys
		"credential key create": {args: []formArg{{ask: "What name should the new key have?", example: "deploy",
			help: "Letters, digits, dot, dash and underscore, starting with a letter or digit. Next, `komando credential key install` puts it on your servers."}},
			flags: []formFlag{{name: "type", ask: "Which kind of key?", choices: []string{"ed25519", "rsa", "ecdsa"},
				help: "ed25519 is short and safe; pick rsa only for an old server that does not take ed25519."}}},
		"credential key add": {args: []formArg{
			{ask: "What name should the key have in komando?", example: "personal", help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."},
			{ask: "Where is the private key file on this computer?", example: "~/.ssh/id_ed25519", local: true,
				help: "The file without .pub at the end. It stays where it is. ~/ means your home folder."}},
			flags: []formFlag{accPassRef}},
		"credential key edit":   {args: []formArg{accKey}, flags: []formFlag{accPassRef}},
		"credential key list":   {},
		"credential key show":   {args: []formArg{accKey}},
		"credential key rename": {args: []formArg{accKey, {ask: "What should the new name be?", example: "deploy-2026", help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}}},
		"credential key remove": {args: []formArg{accKey}, flags: []formFlag{{name: "delete-file", ask: "Also delete the private key?",
			help: "Only for a key komando made. A deleted private key cannot be brought back."}}},
		"credential key install": {args: []formArg{accKeyOrPub, accServers},
			flags: []formFlag{{name: "set-default", ask: "Should komando log in with this key from now on?",
				help: "Yes switches each server where it worked to this key."}},
			hide: []string{"public-key-file", "user", "from-address"}}, // a phone's key takes TARGET alone: typed, not asked
		"credential key uninstall": {args: []formArg{accKeyOrPub, accServers},
			flags: []formFlag{{name: "user", ask: "Whose login should lose the key?", example: "deploy",
				help: "Leave empty for the user komando logs in as. Another user's file is changed with sudo."}}},
	})
}

// The questions for the server CAs (credential certificate).
func init() {
	addFormHints(map[string]formHint{
		"credential certificate list": {},
		"credential certificate add": {
			args: []formArg{{ask: "A short name for this CA?", example: "corp"}},
			flags: []formFlag{
				{name: "key", ask: "The CA's public key file (.pub)?", local: true, example: "~/corp-ca.pub",
					help: "Check its fingerprint with the people who run the CA first: it will vouch for every server it signs."},
				{name: "hosts", ask: "Which server names may it vouch for?", example: "*.corp.example",
					help: "Name at least the domain: *.corp.example or 10.1.2.*. A lone * is refused."},
				{name: "from", ask: "Or read a known_hosts file's @cert-authority lines?", local: true, example: "~/.ssh/known_hosts"},
			},
		},
		"credential certificate remove": {args: []formArg{{ask: "Which CA should komando stop trusting?", help: "See them with `komando credential certificate list`."}}},
	})
}

// loginForm asks for one server: a bare `komando login` only shows its
// help, so a person at a terminal is always asked for the server.
func loginForm(cl *call) []formGroup {
	sp := formSpec{title: "Log in to a server once and keep it", qs: []formQ{{
		key: "arg0", label: "Host", ask: "Which server should you log in to?",
		help:    "komando asks what the server asks (a password, a code from your phone) and keeps the login open for a while, so later commands need no login.",
		choices: func(st *store.State, _ formAnswers) []pickRow { return formPickRows(st, "server") },
	}}}
	sp.build = func(_ *store.State, a formAnswers) [][]string { return [][]string{{"login", a["arg0"]}} }
	return []formGroup{{label: "Login", kinds: []formKind{{label: "Server", spec: func(cl *call) formSpec { return sp }}}}}
}

// Next: lines for VPNs, logins, tunnels, secrets and keys (network,
// secrets, core and cloud areas).
func init() {
	addFormHints(map[string]formHint{
		"login":                 {next: []string{"status", "host ssh exec {} -- uptime", "logout {}"}},
		"logout":                {next: []string{"status"}},
		"host ssh tunnel start": {next: []string{"host ssh tunnel list", "host ssh tunnel stop TUNNEL"}},
		"host ssh tunnel stop":  {next: []string{"host ssh tunnel list"}},
		"login aws":             {next: []string{"test TARGET", "storage s3 object list NAME", "import aws"}},
		"credential password add": {next: []string{"host ssh edit TARGET --credential {}", "conn edit NAME --password-ref credential:{}",
			"credential list"}},
		"credential token add":       {next: []string{"credential list"}},
		"credential list":            {next: []string{"credential password show NAME", "credential password add NAME"}},
		"credential password rename": {next: []string{"credential list", "test TARGET"}},
		"credential token rename":    {next: []string{"credential list"}},
		"secret cp":                  {next: []string{"credential list"}},
		"config vault keychain":      {next: []string{"doctor"}},
		"config vault passphrase":    {next: []string{"doctor", "host ssh tunnel list", "status"}},
		"credential key create":      {next: []string{"credential key install {} TARGET --set-default", "credential key show {}"}},
		"credential key install":     {next: []string{"test TARGET", "credential key uninstall NAME TARGET"}},
	})
}

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
			next: []string{cmd + "start {}", cmd + "test {}", "host ssh add NAME ADDRESS --via {}"}}, true
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
