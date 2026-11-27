package capability

// komando's own nouns: credential, group, policy, snippet, config, agent
// and audit. A credential kind or a part of config is the Area.

func own(typ, area, verb string) Key { return Key{Type: typ, Area: area, Verb: verb} }

// credentialStops: a credential a protected entry uses is protected too.
var credentialStops = []string{"protectedUsers"}

// valueKinds hold one sealed value: a password with its user, or a token.
var valueKinds = []string{"password", "token"}

var credentialLeaves = concat(
	[]Leaf{
		{Key: own("credential", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"secret.list"},
			Options: []Option{limitOpt},
			Short:   "List the saved passwords and tokens, when they changed and what uses them",
			Example: "  komando credential list\n  komando credential list -o json"},
		{Key: own("credential", "", "run"), Args: []Arg{{Name: "PROGRAM", Many: true, Dash: true}},
			Options: []Option{{Name: "env", Short: "e", Kind: String, Repeat: true, Help: "put KEY=VALUE or KEY=secret:NAME in the program's environment (repeatable)"}},
			Stops:   []string{"refuseEncodedSecret", "RefGuard"}, Today: []string{"secret.run"},
			Short: "Run a program on this computer with saved credentials in its environment",
			Example: "  komando credential run --dry-run --env TOKEN=secret:gh-token -- ./deploy.sh\n" +
				"  komando credential run --env PGPASSWORD=secret:db-main -- psql -h 10.0.0.5 -U app\n" +
				"  komando credential run -e AWS_SECRET_ACCESS_KEY=secret:aws-ci -e AWS_REGION=eu-west-1 -- terraform plan"},
	},
	valueKindLeaves(),
	[]Leaf{
		{Key: own("credential", "key", "add"), Args: []Arg{{Name: "NAME"}, {Name: "FILE"}}, Stops: []string{"RefGuard"}, Today: []string{"key.add"},
			Options: []Option{keyPassphraseOpt, keyCertOpt},
			Short:   "Add a private key file you already have (komando keeps its path)",
			Example: "  komando credential key add personal ~/.ssh/id_ed25519 --dry-run\n" +
				"  komando credential key add personal ~/.ssh/id_ed25519\n" +
				"  komando credential key add corp ~/.ssh/id_corp --cert ~/.ssh/corp-ca/id_corp-cert.pub\n" +
				"  komando credential key add work ~/.ssh/id_work --passphrase-credential id-pass"},
		{Key: own("credential", "key", "create"), Args: oneName, Today: []string{"key.gen"},
			Options: []Option{
				{Name: "type", Kind: String, Default: "ed25519", Help: "ed25519 | rsa | ecdsa"},
				{Name: "bits", Short: "b", Kind: Int, Default: "0", Help: "key size: RSA 3072-16384 (default 4096), ECDSA 256|384|521"},
				{Name: "comment", Short: "C", Kind: String, Help: "public key comment (default komando-NAME)"}},
			Short: "Make a new SSH key pair (ed25519 by default)",
			Example: "  komando credential key create deploy --dry-run\n" +
				"  komando credential key create deploy\n" +
				"  komando credential key create legacy --type rsa -b 4096 -C ops@example.com"},
		{Key: own("credential", "key", "edit"), Args: oneName, Stops: append([]string{"RefGuard"}, credentialStops...), Today: []string{"key.edit"},
			Options: []Option{keyPassphraseOpt, {Name: "cert", Kind: File, Help: "an OpenSSH user certificate for the key"},
				{Name: "unset", Kind: String, Repeat: true, List: true, Help: "clear this setting: passphrase-credential, cert"}},
			Short: "Change a key's passphrase credential or certificate",
			Example: "  komando credential key edit work --passphrase-credential work-key-pass --dry-run\n" +
				"  komando credential key edit work --passphrase-credential work-key-pass\n" +
				"  komando credential key edit work --unset passphrase-credential\n" +
				"  komando credential key edit deploy --cert ~/Downloads/deploy-cert.pub"},
		{Key: own("credential", "key", "install"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}}, Today: []string{"key.deploy"},
			Options: []Option{{Name: "set-default", Kind: Bool, Help: "servers that got the key log in with it from now on"}},
			Short:   "Install a public key in ~/.ssh/authorized_keys (like ssh-copy-id)",
			Example: "  komando credential key install deploy @web --dry-run\n" +
				"  komando credential key install deploy @web --set-default\n" +
				"  komando credential key install ~/.ssh/id_ed25519.pub web1"},
		{Key: own("credential", "key", "uninstall"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}}, Today: []string{"key.revoke"},
			Options: []Option{
				{Name: "user", Kind: String, Help: "edit this user's authorized_keys instead of the login user's (uses sudo)"},
				{Name: "all-users", Kind: Bool, Help: "edit every user's authorized_keys on the server (uses sudo)"}},
			Short: "Take a public key off servers' authorized_keys",
			Example: "  komando credential key uninstall ~/keys/alice.pub @web --dry-run\n" +
				"  komando credential key uninstall old-deploy @web --user deploy --dry-run\n" +
				"  komando credential key uninstall ~/keys/alice.pub @web --all-users --dry-run"},
		{Key: own("credential", "key", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"key.list"},
			Options: []Option{limitOpt},
			Short:   "List the SSH keys and the servers that use them",
			Example: "  komando credential key list\n  komando credential key list -o json"},
		{Key: own("credential", "key", "remove"), Args: oneName, Stops: credentialStops,
			Options: []Option{{Name: "delete-file", Kind: Bool, Help: "also delete the private key komando keeps (only keys komando made)"}}, Today: []string{"key.rm"},
			Short: "Remove a key (from komando only)",
			Example: "  komando credential key remove old-ci --dry-run\n" +
				"  komando credential key remove old-ci\n" +
				"  komando credential key remove deploy --delete-file --dry-run"},
		{Key: own("credential", "key", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Today: []string{"key.rename"},
			Short:   "Rename a key, and every server that uses it",
			Example: "  komando credential key rename old-ci ci --dry-run\n  komando credential key rename deploy deploy-2026"},
		{Key: own("credential", "key", "show"), Args: oneName, LocalRead: true, Today: []string{"key.show"},
			Short: "Show a key's public part, or a person its private key",
			Example: "  komando credential key show deploy\n" +
				"  komando credential key show deploy --reveal --dry-run\n" +
				"  komando credential key show deploy --reveal > deploy.key   " + approvalComment},
		{Key: own("credential", "certificate", "add"), Args: oneName, Today: []string{"host.ca.add"},
			Options: []Option{
				{Name: "key", Kind: File, Help: "the CA's public key file (.pub)"},
				{Name: "hosts", Kind: String, Repeat: true, List: true, Help: "server name patterns the CA may vouch for (*.corp.example,10.1.2.*)"},
				{Name: "from", Kind: File, Help: "a known_hosts file: read its @cert-authority and @revoked lines"}},
			Short: "Trust a CA for the servers its patterns match",
			Example: "  komando credential certificate add corp --key ~/corp-ca.pub --hosts '*.corp.example' --dry-run\n" +
				"  komando credential certificate add corp --from ~/.ssh/known_hosts --dry-run"},
		{Key: own("credential", "certificate", "edit"), Args: oneName, State: New},
		{Key: own("credential", "certificate", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"host.ca.list"},
			Options: []Option{{Name: "limit", Short: "n", Kind: Int, Help: "the first N CAs (0 = all)"}},
			Short:   "List the trusted server CAs",
			Example: "  komando credential certificate list\n  komando credential certificate list -o json"},
		{Key: own("credential", "certificate", "remove"), Args: oneName, Today: []string{"host.ca.rm"},
			Short:   "Stop trusting a server CA",
			Example: "  komando credential certificate remove corp --dry-run\n  komando credential certificate remove corp"},
		{Key: own("credential", "certificate", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, State: New},
		{Key: own("credential", "certificate", "show"), Args: oneName, State: New, LocalRead: true},
	},
)

// approvalComment marks an example line that runs only after a person's
// yes (S-6.7); internal/cli checks the same words.
const approvalComment = "# after a person's yes"

var (
	// keyPassphraseOpt names the password credential that opens an
	// encrypted key file. It goes when the key credential holds its own
	// passphrase (cut step E).
	keyPassphraseOpt = Option{Name: "passphrase-credential", Kind: Credential, Help: "the password credential that opens an encrypted key file"}
	keyCertOpt       = Option{Name: "cert", Kind: File, Help: "an OpenSSH user certificate for the key (default: FILE-cert.pub next to it, if there)"}
)

// valueKindLeaves: today's secret commands split into the password and
// token kinds, so they are carried, not kept under one key. Until cut step
// E keeps a kind with each value, both kinds read and write the same
// saved values. edit and list per kind, and add's --store, --item, --user
// and --ask, come with the credential model (gaps.md, deferred rows).
func valueKindLeaves() []Leaf {
	var out []Leaf
	for _, kind := range valueKinds {
		name, example := "web1-pass", "db-pass"
		if kind == "token" {
			name, example = "gh-token", "api-token"
		}
		cmd := "  komando credential " + kind + " "
		out = append(out,
			Leaf{Key: own("credential", kind, "add"), Args: oneName, Stops: []string{"RefGuard"}, Carries: []string{"secret.set"},
				Options: []Option{
					{Name: "from-env", Kind: String, Help: "read the value from this environment variable"},
					{Name: "new", Kind: Bool, Help: "only save one that is not saved yet; a taken NAME stops with SECRET_EXISTS"}},
				Short: "Save a " + kind + ", typed hidden or from a variable or a pipe",
				Example: cmd + "add " + name + " --dry-run\n" +
					cmd + "add " + name + "   # type or paste it after the prompt, nothing is shown\n" +
					cmd + "add " + example + " --new --from-env VALUE"},
			Leaf{Key: own("credential", kind, "edit"), Args: oneName, State: New, Stops: append([]string{"RefGuard"}, credentialStops...)},
			Leaf{Key: own("credential", kind, "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
			Leaf{Key: own("credential", kind, "remove"), Args: []Arg{{Name: "NAME", Many: true}}, Stops: credentialStops, Carries: []string{"secret.rm"},
				Short:   "Delete saved " + kind + "s for good",
				Example: cmd + "remove " + example + " --dry-run\n" + cmd + "remove " + example},
			Leaf{Key: own("credential", kind, "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Carries: []string{"secret.rename"},
				Options: []Option{{Name: "overwrite", Kind: Bool, Help: "replace NEW when it exists (what uses NEW then gets the value of NAME)"}},
				Short:   "Rename a " + kind + " and every reference to it (value never shown)",
				Example: cmd + "rename " + example + " " + example + "-old --dry-run\n" + cmd + "rename " + example + " " + example + "-old"},
			Leaf{Key: own("credential", kind, "show"), Args: oneName, LocalRead: true, Carries: []string{"secret.show"},
				Short: "Show that a " + kind + " is saved and what uses it, its value hidden",
				Example: cmd + "show " + example + "\n" +
					cmd + "show " + example + " --reveal --dry-run\n" +
					cmd + "show " + example + " --reveal | pbcopy   " + approvalComment},
		)
	}
	return out
}

// storeProviders are the outside secret stores a credential can point at.
// Each has typed options; nobody types a raw reference string.
var storeProviders = []provider{
	{name: "vault", state: New, connect: []Option{{Name: "address", Kind: String, Help: "the Vault server's URL"}, credentialOpt}},
	{name: "aws-sm", state: New, connect: []Option{{Name: "region", Kind: String}, {Name: "profile", Kind: String, Help: "the AWS profile to log in with"}}},
	{name: "gcp-sm", state: New, connect: []Option{{Name: "project", Kind: String}}},
	{name: "azure-kv", state: New, connect: []Option{{Name: "vault-url", Kind: String, Help: "the key vault's URL"}}},
	{name: "onepassword", state: New, connect: []Option{{Name: "account", Kind: String}}},
	{name: "bitwarden", state: New, connect: []Option{{Name: "server", Kind: String, Help: "a self-hosted server's URL"}}},
	{name: "keepass", state: New, connect: []Option{{Name: "file", Kind: File, Help: "the .kdbx file"}, credentialOpt}},
	{name: "env", state: New},
	{name: "file", state: New, connect: []Option{{Name: "dir", Kind: File, Help: "the folder the items are files in"}}},
}

// storeInventory: test proves komando can read from the store without
// showing a value; RefGuard checks what a store may point at.
var storeInventory = inventory{typ: "credential", area: "store"}

var storeLeaves = each(storeProviders, func(p provider) []Leaf {
	ls := storeInventory.leaves(p)
	for i := range ls {
		if ls[i].Verb == "add" || ls[i].Verb == "edit" {
			ls[i] = withStop(ls[i:i+1], "RefGuard")[0]
		}
	}
	return ls
})

var readOnlySnippet = Option{Name: "read-only", Kind: Bool, Help: "every step only reads"}

// reservedSecret refuses the approval code's seed on every credential leaf:
// it is an internal record, not a credential.
var ownLeaves = concat(
	withStop(credentialLeaves, "reservedSecret"),
	withStop(storeLeaves, "reservedSecret"),
	[]Leaf{
		{Key: own("group", "", "create"), Args: []Arg{{Name: "NAME"}, {Name: "MEMBER", Many: true, Optional: true}}, Today: []string{"group.add"}},
		{Key: own("group", "", "edit"), Args: oneName, State: New,
			Options: []Option{{Name: "add", Kind: Entry, Repeat: true}, {Name: "remove", Kind: Entry, Repeat: true}}},
		{Key: own("group", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"group.list"}},
		{Key: own("group", "", "show"), Args: oneName, LocalRead: true},
		{Key: own("group", "", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Today: []string{"group.rename"}},
		{Key: own("group", "", "remove"), Args: oneName, Today: []string{"group.rm"}},

		{Key: own("policy", "", "check"), Args: []Arg{{Name: "COMMAND", Many: true}}, LocalRead: true, Today: []string{"policy.check"}},
		{Key: own("policy", "", "create"), Args: []Arg{{Name: "PATTERN"}}, Today: []string{"policy.deny"}},
		{Key: own("policy", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"policy.list"}},
		{Key: own("policy", "", "show"), Args: oneName, LocalRead: true, Today: []string{"policy.show"}},
		{Key: own("policy", "", "edit"), Args: oneName, Today: []string{"policy.edit"},
			Options: []Option{{Name: "off", Kind: Bool, Help: "switch the rule off; --off=false switches it on again everywhere"},
				{Name: "add-server", Kind: Entry, Repeat: true, Help: "with --off: only on these servers"},
				{Name: "add-group", Kind: Entry, Repeat: true, Help: "with --off: only on the servers in these groups as they are now"},
				{Name: "rm-server", Kind: Entry, Repeat: true, Help: "switch the rule on again on these servers"},
				{Name: "rm-group", Kind: Entry, Repeat: true, Help: "switch the rule on again on the servers these groups named"}}},
		{Key: own("policy", "", "remove"), Args: oneName, Today: []string{"policy.rm"}},

		{Key: own("snippet", "", "create"), Args: oneName, Today: []string{"recipe.add"},
			Options: []Option{{Name: "overwrite", Kind: Bool, Help: "replace a snippet of that name"}, readOnlySnippet}},
		{Key: own("snippet", "", "edit"), Args: oneName, State: New, Options: []Option{readOnlySnippet}},
		{Key: own("snippet", "", "exec"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}},
			Output: TargetData, Stops: []string{"refuseEncodedSecret"}, Today: []string{"recipe.run"}},
		{Key: own("snippet", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"recipe.list"}},
		{Key: own("snippet", "", "show"), Args: oneName, State: New, LocalRead: true},
		{Key: own("snippet", "", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, State: New},
		{Key: own("snippet", "", "remove"), Args: oneName, Today: []string{"recipe.rm"}},

		{Key: own("config", "", "get"), Args: []Arg{{Name: "SETTING"}}, Today: []string{"config.get"},
			Short:   "Print one setting",
			Example: "  komando config get parallel\n  komando config get host_key_policy -o text"},
		{Key: own("config", "", "set"), Args: []Arg{{Name: "SETTING"}, {Name: "VALUE"}}, Today: []string{"config.set"},
			Short: "Change a setting",
			Example: "  komando config set parallel 20 --dry-run\n" +
				"  komando config set parallel 20\n" +
				"  komando config set default_timeout 10m\n" +
				"  komando config set audit_sql hash"},
		{Key: own("config", "", "show"), LocalRead: true, Today: []string{"config.show"},
			Short:   "Show settings, their defaults and file locations",
			Example: "  komando config show\n  komando config show -o json"},
		{Key: own("config", "", "approval-code"), Today: []string{"config.approval-code"},
			Options: []Option{{Name: "off", Kind: Bool, Help: "turn the approval code off (needs --yes)"}},
			Short:   "Ask for an authenticator app code in the approval window",
			Example: "  komando config approval-code   # shows a secret to add to your authenticator app\n" +
				"  komando config approval-code --off --dry-run\n" +
				"  komando config approval-code --off --yes   " + approvalComment},
		{Key: own("config", "vault", "keychain"), Today: []string{"secret.keychain"},
			Options: []Option{{Name: "off", Kind: Bool, Help: "move the key back into store.key (needs --yes)"}},
			Short:   "Keep the vault key in the OS keychain instead of store.key",
			Example: "  komando config vault keychain --dry-run\n" +
				"  komando config vault keychain\n" +
				"  komando config vault keychain --off --dry-run\n" +
				"  komando config vault keychain --off --yes   " + approvalComment},
		// it opens the store with the passphrase a person types
		{Key: own("config", "vault", "passphrase"), LocalRead: true, Today: []string{"secret.passphrase"},
			Options: []Option{{Name: "off", Kind: Bool, Help: "back to a random key in store.key (needs --yes)"}},
			Short:   "Change the vault passphrase and encrypt the secrets again",
			Example: "  komando config vault passphrase --dry-run\n" +
				"  komando config vault passphrase   # asks for the new passphrase twice, hidden\n" +
				"  komando config vault passphrase --off --dry-run\n" +
				"  komando config vault passphrase --off --yes   " + approvalComment},

		{Key: own("agent", "skill", "install"), LocalRead: true, Today: []string{"guide.install"}},
		{Key: own("agent", "skill", "uninstall"), LocalRead: true, Today: []string{"guide.uninstall"}},
		{Key: own("agent", "mcp", "start"), State: New},
		{Key: own("agent", "mcp", "stop"), State: New},

		{Key: own("audit", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"audit"}},
		{Key: own("audit", "", "check"), LocalRead: true, Today: []string{"audit.verify"}},
		{Key: own("audit", "", "export"), State: New},
		{Key: own("audit", "recording", "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
		{Key: own("audit", "recording", "show"), Args: oneName, State: New, Output: TargetData},
		{Key: own("audit", "recording", "export"), Args: oneName, State: New, Output: TargetData},
		// remove, not delete: komando's own things use remove
		{Key: own("audit", "recording", "remove"), Args: oneName, State: New},
	},
)
