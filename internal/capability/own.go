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
			Stops:   []string{"refuseEncodedSecret"}, Today: []string{"secret.run"}},
	},
	valueKindLeaves(),
	[]Leaf{
		{Key: own("credential", "key", "add"), Args: oneName, Today: []string{"key.add"}},
		{Key: own("credential", "key", "create"), Args: oneName, Today: []string{"key.gen"}},
		{Key: own("credential", "key", "edit"), Args: oneName, Stops: credentialStops, Today: []string{"key.edit"}},
		{Key: own("credential", "key", "install"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}}, Today: []string{"key.deploy"}},
		{Key: own("credential", "key", "uninstall"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}}, Today: []string{"key.revoke"}},
		{Key: own("credential", "key", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"key.list"}},
		{Key: own("credential", "key", "remove"), Args: oneName, Stops: credentialStops,
			Options: []Option{{Name: "delete-file", Kind: Bool, Help: "also delete the private key komando keeps"}}, Today: []string{"key.rm"}},
		{Key: own("credential", "key", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Today: []string{"key.rename"}},
		{Key: own("credential", "key", "show"), Args: oneName, LocalRead: true, Today: []string{"key.show"}},
		{Key: own("credential", "certificate", "add"), Args: oneName, Today: []string{"host.ca.add"}},
		{Key: own("credential", "certificate", "edit"), Args: oneName, State: New},
		{Key: own("credential", "certificate", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"host.ca.list"}},
		// revoke (a never-trust list) is not the same act as remove: still open
		{Key: own("credential", "certificate", "remove"), Args: oneName, Today: []string{"host.ca.rm"}, Carries: []string{"host.ca.revoke"}},
		{Key: own("credential", "certificate", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, State: New},
		{Key: own("credential", "certificate", "show"), Args: oneName, State: New, LocalRead: true},
	},
)

// valueKindLeaves: today's secret commands split into the password and
// token kinds, so they are carried, not kept under one key.
func valueKindLeaves() []Leaf {
	var out []Leaf
	for _, kind := range valueKinds {
		add := []Option{{Name: "ref", Kind: String, Help: "where the value lives outside komando (env:, file:, op://, ...)"}}
		if kind == "password" {
			add = append(add, Option{Name: "user", Kind: String, Help: "the user name it logs in as"},
				Option{Name: "ask", Kind: Bool, Help: "keep no password: a person types it at each connect"})
		}
		out = append(out,
			Leaf{Key: own("credential", kind, "add"), Args: oneName, Options: add, Stops: []string{"RefGuard"}, Carries: []string{"secret.set"}},
			Leaf{Key: own("credential", kind, "edit"), Args: oneName, Options: clone(add[:1]), Stops: append([]string{"RefGuard"}, credentialStops...)},
			Leaf{Key: own("credential", kind, "list"), LocalRead: true, Synonyms: []string{"ls"}},
			Leaf{Key: own("credential", kind, "remove"), Args: oneName, Stops: credentialStops, Carries: []string{"secret.rm"}},
			Leaf{Key: own("credential", kind, "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, Stops: credentialStops, Carries: []string{"secret.rename"}},
			Leaf{Key: own("credential", kind, "show"), Args: oneName, LocalRead: true, Carries: []string{"secret.show"}},
		)
	}
	return out
}

var readOnlySnippet = Option{Name: "read-only", Kind: Bool, Help: "every step only reads"}

var ownLeaves = concat(
	credentialLeaves,
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
		{Key: own("policy", "", "show"), Args: oneName, State: New, LocalRead: true},
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
		{Key: own("config", "vault", "passphrase"), Today: []string{"secret.passphrase"}},

		{Key: own("agent", "skill", "install"), Today: []string{"guide.install"}},
		{Key: own("agent", "skill", "uninstall"), Today: []string{"guide.uninstall"}},
		{Key: own("agent", "mcp", "start"), State: New},
		{Key: own("agent", "mcp", "stop"), State: New},

		{Key: own("audit", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"audit"}},
		{Key: own("audit", "", "check"), Today: []string{"audit.verify"}},
		{Key: own("audit", "", "export"), State: New},
		{Key: own("audit", "recording", "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
		{Key: own("audit", "recording", "show"), Args: oneName, State: New, Output: TargetData},
		{Key: own("audit", "recording", "export"), Args: oneName, State: New, Output: TargetData},
		// remove, not delete: komando's own things use remove
		{Key: own("audit", "recording", "remove"), Args: oneName, State: New},
	},
)
