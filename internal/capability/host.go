package capability

// host: servers you log in to. A host keeps only the verbs its raw
// command cannot do: exec and shell, plus ssh's trust and
// tunnel. The removed host areas (files, services, packages, ...) are
// carried by exec.

var hostProviders = []provider{
	{name: "ssh", connect: []Option{credentialOpt,
		{Name: "sudo-credential", Kind: Credential, Help: "the password sudo asks for (today's --sudo-ref)"},
		{Name: "proxy-command", Kind: String, Help: "a program on this computer that makes the connection"}}},
	{name: "winrm", connect: []Option{credentialOpt}},
	{name: "telnet", state: New, connect: []Option{credentialOpt}},
	{name: "serial", state: New},
}

var hostInventory = inventory{
	typ: "host",
	today: ids{"add": {"host.add"}, "edit": {"host.edit"}, "list": {"host.list"}, "remove": {"host.rm"},
		"rename": {"host.rename"}, "show": {"host.show"}, "test": {"host.test"}},
	twin:  "protectedTwinHost",
	guard: "guardProtection",
}

// sshExecCarries are the commands of today that host ssh exec does now.
var sshExecCarries = join(
	idsOf("fs", "cat", "chmod", "list", "mkdir", "mv", "replace", "restore", "rm", "stat", "write"),
	idsOf("svc", "daemon-reload", "disable", "enable", "list", "logs", "reload", "restart", "start", "status", "stop"),
	idsOf("pkg", "install", "installed", "rm", "security", "update", "upgradable", "upgrade"),
	idsOf("net", "check", "dns", "http", "ports"),
	idsOf("cron", "list", "rm", "set"),
	idsOf("user", "add", "list", "lock", "rm", "unlock"),
	idsOf("docker", "compose", "exec", "images", "inspect", "logs", "prune", "ps", "pull", "raw", "restart",
		"rm", "start", "stats", "stop"),
	[]string{"logs", "facts", "reboot"},
	idsOf("job", "kill", "logs", "rm", "start", "status", "wait"),
)

var endOpt = Option{Name: "end", Kind: Bool, Help: "end the session a person's login keeps open"}

var readOnlyOpt = Option{Name: "read-only", Kind: Bool, Help: "the command only reads (the policy checks it either way)"}

var attachOpt = Option{Name: "attach", Kind: String, Pattern: sessionID, Help: "come back to the session with this ID"}

// sessionOpts are exec's server-side session: an agent comes back to a
// long command with --attach ID.
var sessionOpts = []Option{
	attachOpt,
	{Name: "stop", Kind: Bool, Needs: []string{"attach"}, Help: "stop the session's command"},
	{Name: "signal", Kind: Enum, Enum: []string{"TERM", "INT", "KILL", "HUP"}, Default: "TERM",
		Needs: []string{"stop"}, Help: "the signal --stop sends"},
	{Name: "remove", Kind: Bool, Needs: []string{"attach"}, Conflicts: []string{"stop"},
		Help: "remove a finished session's log from the server"},
}

var hostLeaves = concat(
	each(hostProviders, hostInventoryFor),
	[]Leaf{
		{Key: Key{Type: "host", Provider: "ssh", Verb: "exec"}, Args: selectorAndCommand,
			Options: append([]Option{readOnlyOpt}, sessionOpts...), Output: TargetData,
			Stops: []string{"refuseEncodedSecret"}, Today: []string{"exec"}, Carries: sshExecCarries},
		{Key: Key{Type: "host", Provider: "winrm", Verb: "exec"}, Args: selectorAndCommand,
			Options: []Option{readOnlyOpt}, Output: TargetData,
			Stops: []string{"refuseEncodedSecret"}, Today: []string{"exec"}},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "shell"}, Args: oneName,
			Options: []Option{attachOpt}, Today: []string{"shell"}},
		{Key: Key{Type: "host", Provider: "winrm", Verb: "shell"}, Args: oneName, Today: []string{"shell"}},
		{Key: Key{Type: "host", Provider: "telnet", Verb: "shell"}, Args: oneName, State: New},
		{Key: Key{Type: "host", Provider: "serial", Verb: "shell"}, Args: oneName, State: New},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "trust"}, Args: oneName,
			Options: []Option{{Name: "reset", Kind: Bool, Help: "replace a pinned host key"}}, Today: []string{"host.trust"}},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "start"}, Args: oneName,
			Options: []Option{{Name: "bind", Kind: String, Default: "127.0.0.1", Help: "the local address to listen on"}},
			Today:   []string{"tunnel.start"}},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "list"}, LocalRead: true,
			Synonyms: []string{"ls"}, Today: []string{"tunnel.list"}},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "stop"}, Args: []Arg{{Name: "ID"}},
			Today: []string{"tunnel.stop"}},
	},
)

func hostInventoryFor(p provider) []Leaf {
	ls := hostInventory.leaves(p)
	if p.name == "ssh" {
		for i := range ls {
			if ls[i].Verb == "test" {
				// the person step of a two-factor server happens in test, and
				// --end ends the session it keeps
				ls[i].Options = append(ls[i].Options, endOpt)
				ls[i].Carries = []string{"login", "logout"}
			}
		}
	}
	return ls
}

var (
	oneName            = []Arg{{Name: "NAME"}}
	selectorAndCommand = []Arg{{Name: "NAME", Selector: true}, {Name: "COMMAND", Many: true, Optional: true}}
)
