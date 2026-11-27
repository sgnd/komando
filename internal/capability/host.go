package capability

import "strings"

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
	hostRun(),
)

// The options of the host inventory. A provider takes the ones its
// connection has (a WinRM server has no key, no sudo, no proxy command).
var (
	hostAddressOpt  = Option{Name: "address", Kind: String, Help: "the host name or IP address, instead of the second word"}
	hostPortOpt     = Option{Name: "port", Kind: Int, Help: "the port"}
	hostUserOpt     = Option{Name: "user", Kind: String, Help: "the user to log in as"}
	hostKeyOpt      = Option{Name: "key", Kind: Entry, Help: "the name of a key in komando's key list"}
	hostIdentityOpt = Option{Name: "identity", Kind: File, Help: "the path of a private key file"}
	hostLoginOpt    = Option{Name: "login", Kind: Enum, Enum: []string{"ask", "password", "key", "agent"},
		Help: "how komando logs in: ask at every connect, a stored password, a key, or the ssh-agent"}
	hostOSOpt  = Option{Name: "os", Kind: Enum, Enum: []string{"windows", "linux"}, Help: "the server's OS: windows runs commands in PowerShell"}
	hostSSMOpt = Option{Name: "ssm", Kind: Bool, Help: "reach it through AWS Systems Manager; the address is the instance ID"}
	hostEnvOpt = Option{Name: "env", Short: "e", Kind: String, Repeat: true, Pairs: true, Help: "env KEY=VALUE exported before every command"}
	hostFwdOpt = Option{Name: "forward-agent", Kind: Bool, Help: "lend the server your ssh-agent while komando is connected (asks first)"}
)

var (
	hostGroupOpt = withShort(groupOpt, "g")
	hostTagOpt   = withShort(tagOpt, "t")
)

// withShort is o with a one-letter name, as today's host add and edit take -g and -t.
func withShort(o Option, short string) Option {
	o.Short = short
	return o
}

// hostSettings are the options add takes for a provider, before the
// common ones.
func hostSettings(p provider) []Option {
	o := []Option{hostAddressOpt, hostPortOpt, hostUserOpt}
	if p.name == "ssh" {
		o = append(o, hostKeyOpt, hostIdentityOpt)
	}
	o = append(o, credentialOpt)
	if p.name == "ssh" {
		o = append(o, hostOption(p.connect, "sudo-credential"), hostOption(p.connect, "proxy-command"))
	}
	o = append(o, hostLoginOpt, viaOpt)
	if p.name == "ssh" {
		o = append(o, hostOSOpt, hostSSMOpt)
	}
	return o
}

func hostInventoryFor(p provider) []Leaf {
	ls := hostInventory.leaves(p)
	if p.state != Built {
		return ls
	}
	for i := range ls {
		completeHost(&ls[i], p)
	}
	return ls
}

// completeHost gives a host inventory leaf the arguments, options and texts
// of the command of today it keeps.
func completeHost(l *Leaf, p provider) {
	cmd := "  komando host " + p.name + " "
	lines := func(l ...string) string { return strings.Join(l, "\n") }
	what := map[string]string{"ssh": "an SSH server", "winrm": "a Windows server over WinRM"}[p.name]
	many := map[string]string{"ssh": "SSH servers", "winrm": "WinRM servers"}[p.name]
	addr, entry := "deploy@10.0.0.11", "web1"
	if p.name == "winrm" {
		addr, entry = "Administrator@10.0.0.9", "web1"
	}
	switch l.Verb {
	case "add":
		l.Args = []Arg{{Name: "NAME"}, {Name: "ADDRESS", Optional: true}}
		l.Options = append(hostSettings(p), protectedOpt, hostGroupOpt, hostTagOpt, labelOpt, hostEnvOpt, notesOpt, askPassOpt, overwriteOp)
		l.Short = "Save " + what + " under a short name"
		l.Example = lines(cmd+"add "+entry+" "+addr+" --group web --tag prod", cmd+"add "+entry+" "+addr+" --dry-run",
			cmd+"add db1 --address db.internal --user root --via web1 --protected")
	case "edit":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Many: true}}
		var o []Option
		for _, a := range hostSettings(p) {
			if a.Name != "ssm" {
				o = append(o, a)
			}
		}
		unset := []string{"user", "key", "identity", "credential", "sudo-credential", "via", "proxy-command", "notes", "port", "protected", "forward-agent", "os", "transport"}
		if p.name == "winrm" {
			unset = []string{"user", "credential", "via", "notes", "port", "protected"}
		}
		o = append(o, protectedOpt, notesOpt, labelOpt, hostEnvOpt,
			withShort(hostOption(connEditOptions, "add-group"), "g"), hostOption(connEditOptions, "rm-group"),
			withShort(hostOption(connEditOptions, "add-tag"), "t"), hostOption(connEditOptions, "rm-tag"), askPassOpt)
		if p.name == "ssh" {
			o = append(o, hostFwdOpt)
		}
		o = append(o, Option{Name: "unset", Kind: String, Repeat: true, List: true, Help: "clear these settings: " + strings.Join(unset, ", ")})
		l.Options = o
		l.Short = "Change saved " + many + " (only the flags you pass change)"
		l.Example = lines(cmd+"edit web1 --add-tag canary --label env=prod", cmd+"edit @web --user deploy --dry-run",
			cmd+"edit db1 --protected")
	case "list":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Optional: true}}
		l.Options = []Option{limitOpt}
		l.Short = "List the saved " + many
		l.Example = lines(cmd+"list", cmd+"list @web")
	case "show":
		l.Short = "Show a saved " + p.name + " server's settings (credentials as names)"
		l.Example = lines(cmd+"show web1", cmd+"show web1 -o json")
	case "rename":
		l.Short = "Rename a saved " + p.name + " server and every reference to it"
		l.Example = lines(cmd+"rename web1 web-01 --dry-run", cmd+"rename web1 web-01")
	case "remove":
		l.Args = []Arg{{Name: "TARGET", Selector: true, Many: true}}
		l.Short = "Forget saved " + many + " (the servers are not touched)"
		l.Example = lines(cmd+"remove web3 --dry-run", cmd+"remove @old")
	case "test":
		l.Args = []Arg{{Name: "TARGET", Selector: true}}
		l.Options = []Option{endOpt, waitOpt}
		l.Short = "Check that saved " + many + " answer and let you in"
		l.Example = lines(cmd+"test @web", cmd+"test @new --wait 5m", cmd+"test --end")
		// login and logout stay top-level commands until the person step moves
		// into test (cut plan C325): host ssh test does not log in yet
	}
}

// hostExecArgs are the arguments of exec: the servers, then the command
// after `--`.
var hostExecArgs = []Arg{{Name: "TARGET", Selector: true}, {Name: "COMMAND", Many: true, Optional: true, Dash: true}}

// execOptions are exec's options: what it runs, how, and its sessions.
func execOptions(sudo bool) []Option {
	o := []Option{
		{Name: "cmd", Short: "c", Kind: String, Help: "the command as one string, instead of the words after --"},
		{Name: "script", Kind: File, Help: "run this script from this computer ('-' is komando's stdin); nothing is left on the server"},
		{Name: "interpreter", Kind: String, Needs: []string{"script"}, Help: "the interpreter on the server (default: from the #! line, else sh)"},
		{Name: "arg", Kind: String, Repeat: true, Needs: []string{"script"}, Help: "an argument for the script, $1 and on"},
		readOnlyOpt,
	}
	if sudo {
		o = append(o,
			Option{Name: "sudo", Short: "s", Kind: Bool, Help: "run with sudo (it never prompts; it uses the server's sudo credential)"},
			Option{Name: "sudo-user", Kind: String, Help: "run as this user with sudo -u"})
	}
	o = append(o,
		Option{Name: "env", Short: "e", Kind: String, Repeat: true, Help: "export KEY=VALUE before the command"},
		Option{Name: "dir", Short: "C", Kind: String, Help: "the working folder on the server"},
		Option{Name: "stream", Kind: Bool, Help: "print the output as NDJSON events while it runs"},
		Option{Name: "fail-fast", Kind: Bool, Help: "start no more servers after the first failure"},
		Option{Name: "stdin-file", Kind: File, Help: "send this file as stdin ('-' is komando's stdin)"},
		Option{Name: "pty", Kind: Bool, Help: "ask for a pseudo-terminal (some tools need one)"})
	return o
}

// shellArgs are the arguments of shell: the server. Words after it are
// refused with the way to run a command (exec).
var shellArgs = []Arg{{Name: "NAME"}, {Name: "COMMAND", Many: true, Optional: true, Dash: true}}

func hostRun() []Leaf {
	execAttach := attachOpt
	execAttach.Repeat, execAttach.List = true, true
	execAttach.Help = "read the rest of these sessions on one server, and their exit codes"
	session := append([]Option{execAttach,
		{Name: "offset", Kind: Int, Needs: []string{"attach"}, Help: "start at this byte of the log (next_from of the last read)"},
		{Name: "wait", Kind: Duration, Default: "1m", Help: "wait this long for the run to end; it goes on after (exit 7); 0 returns at once"},
		{Name: "log-max", Kind: Bytes, Default: "1GiB", Help: "bytes of output the server keeps for the run; more is dropped"}},
		sessionOpts[1:]...)
	execShort := "Run a command on saved servers, in parallel"
	execEx := func(p string) string {
		return strings.Join([]string{"  komando host " + p + " exec web1 -- uptime", "  komando host " + p + " exec @web -P 20 -- 'df -h / | tail -1'",
			"  komando host " + p + " exec db1 --read-only -- df -h"}, "\n")
	}
	return []Leaf{
		{Key: Key{Type: "host", Provider: "ssh", Verb: "exec"}, Args: hostExecArgs,
			Options: append(execOptions(true), session...), Output: TargetData, Short: execShort, Example: execEx("ssh") +
				"\n  komando host ssh exec @web --script ./deploy.sh --arg v1.2.3 --sudo",
			Stops: []string{"refuseEncodedSecret"}, Today: []string{"exec"}, Carries: sshExecCarries},
		{Key: Key{Type: "host", Provider: "winrm", Verb: "exec"}, Args: hostExecArgs,
			Options: execOptions(false), Output: TargetData, Short: execShort + " (PowerShell)", Example: execEx("winrm"),
			Stops: []string{"refuseEncodedSecret"}, Today: []string{"exec"}},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "shell"}, Args: shellArgs,
			Options: []Option{attachOpt}, Short: "Open a login shell on one server (a person at a terminal)",
			Example: "  komando host ssh shell web1\n  komando host ssh shell db1", Today: []string{"shell"}},
		{Key: Key{Type: "host", Provider: "winrm", Verb: "shell"}, Args: shellArgs,
			Short: "Say that a Windows server has no interactive shell here", Example: "  komando host winrm shell web1\n  komando host winrm shell win1", Today: []string{"shell"}},
		{Key: Key{Type: "host", Provider: "telnet", Verb: "shell"}, Args: oneName, State: New},
		{Key: Key{Type: "host", Provider: "serial", Verb: "shell"}, Args: oneName, State: New},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "trust"}, Args: []Arg{{Name: "TARGET", Selector: true}},
			Options: []Option{{Name: "reset", Kind: Bool, Help: "replace a pinned host key"},
				{Name: "fingerprint", Kind: String, Help: "pin the key only when the server shows this fingerprint (SHA256:...)"}},
			Short: "Pin the SSH host keys of servers (--reset after a rebuild)", Today: []string{"host.trust"},
			Example: "  komando host ssh trust web1\n  komando host ssh trust web1 --reset --dry-run\n  komando host ssh trust @web"},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "start"}, Args: []Arg{{Name: "TARGET"}},
			Options: []Option{{Name: "local", Short: "L", Kind: String, Help: "local forward [bind:]LPORT:RHOST:RPORT"},
				{Name: "remote", Short: "R", Kind: String, Help: "remote forward [rbind:]RPORT:LHOST:LPORT"},
				{Name: "dynamic", Short: "D", Kind: String, Help: "SOCKS5 proxy [bind:]PORT"},
				{Name: "port", Kind: Int, Help: "with a saved entry as TARGET: the local port (default: a free one)"}},
			Short: "Start a background tunnel through a server, a VPN or an entry's --via path",
			Example: "  komando host ssh tunnel start prod-db --dry-run\n  komando host ssh tunnel start prod-db --port 15432\n" +
				"  komando host ssh tunnel start web1 -L 8080:localhost:80\n  komando host ssh tunnel start bastion -D 1080",
			Today: []string{"tunnel.start"}},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "list"}, LocalRead: true,
			Options: []Option{limitOpt}, Short: "List tunnels and whether each is up",
			Example: "  komando host ssh tunnel list\n  komando host ssh tunnel list -o json", Synonyms: []string{"ls"}, Today: []string{"tunnel.list"}},
		{Key: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "stop"}, Args: []Arg{{Name: "ID", Many: true, Optional: true}},
			Options: []Option{{Name: "all", Kind: Bool, Help: "stop every tunnel"}}, Short: "Stop tunnels by ID",
			Example: "  komando host ssh tunnel stop t1102\n  komando host ssh tunnel stop --all --dry-run", Today: []string{"tunnel.stop"}},
	}
}

var (
	oneName            = []Arg{{Name: "NAME"}}
	selectorAndCommand = []Arg{{Name: "NAME", Selector: true}, {Name: "COMMAND", Many: true, Optional: true}}
)

// hostOption is the option of os with this name; a name the list does not
// hold is a bug in the table.
func hostOption(os []Option, name string) Option {
	for _, o := range os {
		if o.Name == name {
			return o
		}
	}
	panic("capability: no option " + name)
}
