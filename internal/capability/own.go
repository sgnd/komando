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
		{Key: own("credential", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"secret.list"}},
		{Key: own("credential", "", "run"), Args: []Arg{{Name: "PROGRAM", Many: true}},
			Options: []Option{{Name: "env", Kind: String, Repeat: true, Help: "KEY=credential:NAME, put in the program's environment"}},
			Stops:   []string{"refuseEncodedSecret", "RefGuard"}, Today: []string{"secret.run"}},
	},
	valueKindLeaves(),
	[]Leaf{
		{Key: own("credential", "key", "add"), Args: oneName, Today: []string{"key.add"}},
		{Key: own("credential", "key", "create"), Args: oneName, Today: []string{"key.gen"}},
		{Key: own("credential", "key", "edit"), Args: oneName, Stops: credentialStops, Today: []string{"key.edit"}},
		// the --public-key-file form (C372) installs a device's key for a
		// user, behind the server's own gate: no NAME then, person tier
		{Key: own("credential", "key", "install"), Args: []Arg{{Name: "NAME", Optional: true}, {Name: "TARGET", Selector: true}},
			Options: []Option{
				{Name: "public-key-file", Kind: File, Needs: []string{"user"}, Help: "a device's public key file (a phone's): install it for --user behind the server's own komando gate"},
				{Name: "user", Kind: String, Needs: []string{"public-key-file"}, Pattern: `^[A-Za-z_][A-Za-z0-9._-]{0,31}$`, Help: "the user the device logs in as (never root)"},
				{Name: "from-address", Kind: String, Needs: []string{"public-key-file"}, Help: "the addresses the device logs in from, as the server sees them"},
			}, Today: []string{"key.deploy"}},
		{Key: own("credential", "key", "uninstall"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}}, Today: []string{"key.revoke"}},
		{Key: own("credential", "key", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"key.list"}},
		{Key: own("credential", "key", "remove"), Args: oneName, Stops: credentialStops,
			Options: []Option{{Name: "delete-file", Kind: Bool, Help: "also delete the private key komando keeps"}}, Today: []string{"key.rm"}},
		{Key: own("credential", "key", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Today: []string{"key.rename"}},
		{Key: own("credential", "key", "show"), Args: oneName, LocalRead: true, Today: []string{"key.show"}},
		{Key: own("credential", "certificate", "add"), Args: oneName, Today: []string{"host.ca.add"}},
		{Key: own("credential", "certificate", "edit"), Args: oneName, State: New},
		{Key: own("credential", "certificate", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"host.ca.list"}},
		{Key: own("credential", "certificate", "remove"), Args: oneName, Today: []string{"host.ca.rm"}},
		{Key: own("credential", "certificate", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, State: New},
		{Key: own("credential", "certificate", "show"), Args: oneName, State: New, LocalRead: true},
	},
)

// valueKindLeaves: today's secret commands split into the password and
// token kinds, so they are carried, not kept under one key.
func valueKindLeaves() []Leaf {
	var out []Leaf
	for _, kind := range valueKinds {
		add := []Option{
			{Name: "store", Kind: Entry, Help: "the outside store that holds the value (credential store)"},
			{Name: "item", Kind: String, Needs: []string{"store"}, Help: "the item in that store"},
		}
		if kind == "password" {
			add = append(add, Option{Name: "user", Kind: String, Help: "the user name it logs in as"},
				Option{Name: "ask", Kind: Bool, Help: "keep no password: a person types it at each connect"})
		}
		out = append(out,
			Leaf{Key: own("credential", kind, "add"), Args: oneName, Options: add, Stops: []string{"RefGuard"}, Carries: []string{"secret.set"}},
			Leaf{Key: own("credential", kind, "edit"), Args: oneName, Options: clone(add[:2]), Stops: append([]string{"RefGuard"}, credentialStops...)},
			Leaf{Key: own("credential", kind, "list"), LocalRead: true, Synonyms: []string{"ls"}},
			Leaf{Key: own("credential", kind, "remove"), Args: oneName, Stops: credentialStops, Carries: []string{"secret.rm"}},
			Leaf{Key: own("credential", kind, "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Carries: []string{"secret.rename"}},
			Leaf{Key: own("credential", kind, "show"), Args: oneName, LocalRead: true, Carries: []string{"secret.show"}},
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

		{Key: own("config", "", "get"), Args: []Arg{{Name: "SETTING"}}, Today: []string{"config.get"}},
		{Key: own("config", "", "set"), Args: []Arg{{Name: "SETTING"}, {Name: "VALUE"}}, Today: []string{"config.set"}},
		{Key: own("config", "", "show"), LocalRead: true, Today: []string{"config.show"}},
		{Key: own("config", "", "approval-code"), Today: []string{"config.approval-code"}},
		{Key: own("config", "vault", "keychain"), Today: []string{"secret.keychain"},
			Options: []Option{{Name: "off", Kind: Bool, Help: "move the key out of the keychain"}}},
		// it opens the store with the passphrase a person types
		{Key: own("config", "vault", "passphrase"), LocalRead: true, Today: []string{"secret.passphrase"}},

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
