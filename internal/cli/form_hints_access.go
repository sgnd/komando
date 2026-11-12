package cli

import "github.com/sgnd/komando/internal/store"

// The questions for the VPNs, logins and tunnels area and the Secrets and
// keys area. vpn add has a hand-made form (form_vpn.go).

// Answers several hints share.
var (
	accVpn = formArg{ask: "Which VPN?", pick: "vpn",
		help: "One from your list. `komando vpn list` shows them."}
	accVpns = formArg{ask: "Which VPNs?", pick: "vpn",
		help: "Pick one, or type several names separated by spaces."}
	accNewName = formArg{ask: "What should the new name be?", example: "office-jkt",
		help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}
	accSecret = formArg{ask: "Which secret?", example: "db-pass", pick: "secret", free: true,
		help: "The name you saved it under. komando secret list shows your saved passwords."}
	accSecretNew = formArg{ask: "What should the new name be?", example: "db-pass-old",
		help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}
	accOverwrite = formFlag{name: "overwrite", ask: "Replace the new name if it exists already?",
		help: "No stops when a secret with the new name is there, so nothing is lost by mistake."}
	accKey = formArg{ask: "Which key?", pick: "key",
		help: "One of your komando SSH keys. `komando key list` shows them."}
	accKeyOrPub = formArg{ask: "Which key?", pick: "key", free: true, local: true, example: "~/.ssh/id_ed25519.pub",
		help: "One of your komando SSH keys, or type the path of a .pub file on this computer."}
	accServers = formArg{ask: "On which servers?", pick: "host", free: true,
		help: "Pick one from your list, or type @group, tag:prod or several names separated by spaces or commas."}
	accPassRef = formFlag{name: "passphrase-ref", ask: "Where is the key's passphrase kept?", example: "secret:work-key-pass",
		help: "Only for a key that has a passphrase. Store it first with `komando secret set NAME` (it asks hidden), then type secret:NAME here. Leave empty for a key without one."}
	accSecretOff = formFlag{name: "off", ask: "Move the key back into the store.key file instead?",
		help: "No is the usual answer. Yes makes a copy of ~/.komando open the vault again, so komando asks you to confirm first."}
)

func init() {
	addFormHints(map[string]formHint{
		// VPNs
		"vpn up": {args: []formArg{{ask: "Which VPN should connect?", pick: "vpn",
			help: "It stays up for later commands. When it asks for a login or a code, type it here."}}},
		"vpn down": {args: []formArg{{ask: "Which VPNs should disconnect? (leave empty with --all)", pick: "vpn",
			help: "Pick one, or type several names separated by spaces."}},
			flags: []formFlag{{name: "all", ask: "Disconnect every VPN instead?", help: "Yes disconnects every VPN that is up now."}}},
		"vpn status": {},
		"vpn list": {args: []formArg{{ask: "Only some VPNs? (leave empty for all)", pick: "vpn", free: true,
			help: "Pick one, or type @group or tag:office."}}},
		"vpn show": {args: []formArg{accVpn}},
		"vpn test": {args: []formArg{{ask: "Which VPN should be tested?", pick: "vpn",
			help: "komando connects through it and says whether it works."}},
			flags: []formFlag{{name: "wait", ask: "Keep trying for how long?", example: "5m",
				help: "Like 30s or 5m: it tests again every few seconds until it works. Leave empty to test once."}}},
		"vpn edit": {args: []formArg{accVpn},
			flags: []formFlag{
				{name: "check", ask: "Which address can only be reached through this VPN?", example: "10.0.0.5:22",
					help: "An address and port inside the private network. komando connects to it to see that the VPN works. Leave empty to keep it."},
				{name: "user", ask: "New user name for the VPN login?", example: "alice",
					help: "Leave empty to keep it."},
				{name: "password-ref", ask: "Where is the new password kept?", example: "secret:office-pass",
					help: "Store it first with `komando secret set NAME` (it asks hidden), then type secret:NAME here. Leave empty to keep it."},
				{name: "notes", ask: "Notes about this VPN?", example: "office in Jakarta, ask Budi for access",
					help: "Anything to remember. Leave empty to keep them."},
			}},
		"vpn mv": {args: []formArg{accVpn, accNewName}},
		"vpn rm": {args: []formArg{accVpns}},

		// Tunnels
		"tunnel start": {args: []formArg{{ask: "To which server or service?", pick: "target", free: true,
			help: "Pick a service (a database, a cache) to reach it from this computer, or a server to forward a port through it."}},
			flags: []formFlag{
				{name: "port", ask: "Which port on this computer? (for a service)", example: "15432",
					help: "Point your app at localhost and this port. Leave empty for a free one; komando shows which."},
				{name: "local", ask: "What should it forward? (for a server)", example: "8080:localhost:80",
					help: "LOCALPORT:ADDRESS:PORT: localhost:8080 here reaches localhost:80 as the server sees it. Leave empty for a service."},
			}},
		"tunnel list": {},
		"tunnel stop": {args: []formArg{{ask: "Which tunnels should stop? (leave empty with --all)", pick: "tunnel", free: true,
			help: "Their IDs: `komando tunnel list` shows them. Several: separate them with spaces."}},
			flags: []formFlag{{name: "all", ask: "Stop every tunnel instead?"}}},

		// Logins
		"login": {form: loginForm},
		"login aws": {flags: []formFlag{{name: "profile", ask: "Which AWS profile?", example: "prod",
			help: "Its name in ~/.aws/config. Leave empty for the usual one. Your browser opens for the AWS sign-in."}}},
		"logout": {args: []formArg{{ask: "From which servers? (leave empty with --all)", pick: "host", free: true,
			help: "Ends the login `komando login` kept. Several: separate them with spaces."}},
			flags: []formFlag{{name: "all", ask: "End every kept login instead?"}}},

		// Secrets
		"secret set": {args: []formArg{{ask: "What name should the secret have?", example: "db-pass", pick: "secret", free: true,
			help: "Pick one to give it a new value, or type a new name: letters, digits, dot, dash and underscore, starting with a letter or digit. komando asks for the value next and hides it as you type or paste."}}},
		"secret get": {args: []formArg{accSecret}},
		"secret check": {args: []formArg{{ask: "Which secret should your value be compared with?", example: "vpn-pass", pick: "secret", free: true,
			help: "Its name in the vault. komando asks for your value next, hidden, and says whether it matches, never showing either."}}},
		"secret list": {},
		"secret mv":   {args: []formArg{accSecret, accSecretNew}, flags: []formFlag{accOverwrite}},
		"secret cp":   {args: []formArg{accSecret, accSecretNew}, flags: []formFlag{accOverwrite}},
		"secret rm": {args: []formArg{{ask: "Which secrets?", example: "old-pass", pick: "secret", free: true,
			help: "Their names in the vault. Several: separate them with spaces. A secret still in use is not deleted."}}},
		"secret keychain": {flags: []formFlag{accSecretOff}},
		"secret passphrase": {flags: []formFlag{{name: "off", ask: "Go back to a random key in store.key instead?",
			help: "No is the usual answer: komando asks for the new passphrase twice, hidden. Yes asks you to confirm first."}}},

		// SSH keys
		"key gen": {args: []formArg{{ask: "What name should the new key have?", example: "deploy",
			help: "Letters, digits, dot, dash and underscore, starting with a letter or digit. Next, `komando key deploy` puts it on your servers."}},
			flags: []formFlag{{name: "type", ask: "Which kind of key?", choices: []string{"ed25519", "rsa", "ecdsa"},
				help: "ed25519 is short and safe; pick rsa only for an old server that does not take ed25519."}}},
		"key add": {args: []formArg{
			{ask: "What name should the key have in komando?", example: "personal", help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."},
			{ask: "Where is the private key file on this computer?", example: "~/.ssh/id_ed25519", local: true,
				help: "The file without .pub at the end. It stays where it is. ~/ means your home folder."}},
			flags: []formFlag{accPassRef}},
		"key edit": {args: []formArg{accKey}, flags: []formFlag{accPassRef}},
		"key list": {},
		"key show": {args: []formArg{accKey}},
		"key mv":   {args: []formArg{accKey, {ask: "What should the new name be?", example: "deploy-2026", help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}}},
		"key rm": {args: []formArg{accKey}, flags: []formFlag{{name: "delete-file", ask: "Also delete the key files?",
			help: "Only for a key komando made. Deleted key files cannot be brought back."}}},
		"key deploy": {args: []formArg{accKeyOrPub, accServers},
			flags: []formFlag{{name: "set-default", ask: "Should komando log in with this key from now on?",
				help: "Yes switches each server where it worked to this key."}}},
		"key revoke": {args: []formArg{accKeyOrPub, accServers},
			flags: []formFlag{{name: "user", ask: "Whose login should lose the key?", example: "deploy",
				help: "Leave empty for the user komando logs in as. Another user's file is changed with sudo."}}},
	})
}

// loginForm asks for one server: a bare `komando login` only shows its
// help, so a person at a terminal is always asked for the server.
func loginForm() []formGroup {
	sp := formSpec{title: "Log in to a server once and keep it", qs: []formQ{{
		key: "arg0", label: "Host", ask: "Which server should you log in to?",
		help:    "komando asks what the server asks (a password, a code from your phone) and keeps the login open for a while, so later commands need no login.",
		choices: func(st *store.State, _ formAnswers) []menuRow { return formPickRows(st, "server") },
	}}}
	sp.build = func(_ *store.State, a formAnswers) [][]string { return [][]string{{"login", a["arg0"]}} }
	return []formGroup{{label: "Login", kinds: []formKind{{label: "Server", spec: func() formSpec { return sp }}}}}
}

// Next: lines for VPNs, logins, tunnels, secrets and keys (network,
// secrets, core and cloud areas).
func init() {
	addFormHints(map[string]formHint{
		"vpn up":       {next: []string{"vpn status", "test TARGET", "vpn down {}"}},
		"vpn down":     {next: []string{"vpn status", "vpn up {}"}},
		"login":        {next: []string{"status", "exec {} -- uptime", "logout {}"}},
		"logout":       {next: []string{"status"}},
		"tunnel start": {next: []string{"tunnel list", "tunnel stop ID"}},
		"tunnel stop":  {next: []string{"tunnel list"}},
		"login aws":    {next: []string{"test CONN", "storage ls CONN", "import aws"}},
		"secret set": {next: []string{"host edit HOST --password-ref secret:{}", "conn edit CONN --password-ref secret:{}",
			"secret list"}},
		"secret list":       {next: []string{"secret get NAME", "secret set NAME"}},
		"secret mv":         {next: []string{"secret list", "test TARGET"}},
		"secret cp":         {next: []string{"secret list"}},
		"secret keychain":   {next: []string{"doctor"}},
		"secret passphrase": {next: []string{"doctor", "tunnel list", "vpn status"}},
		"key gen":           {next: []string{"key deploy {} TARGET --set-default", "key show {}"}},
		"key deploy":        {next: []string{"test TARGET", "key revoke OLD_KEY TARGET"}},
	})
}
