package cli

import "github.com/spf13/cobra"

// What each command does, in one word, so that agents (through `komando
// schema`) and reviewers see it without reading the code:
//
//   - read: changes nothing on servers, resources or the inventory (it may
//     save a file you asked for on this computer, like `download`);
//   - change: changes a server, a resource, or komando's own inventory,
//     settings, vault or background sessions;
//   - depends: it depends on a flag or on the command it runs; the note
//     says on what.
//
// Every runnable command must be in commandKinds (TestEveryCommandHasKind
// checks). The safety checks themselves (Guard, GuardConns,
// guardProtection, ...) stay where they are; this table only names them.
const (
	kindRead    = "read"
	kindChange  = "change"
	kindDepends = "depends"
)

type cmdKind struct {
	Kind string
	Note string // why, for kindDepends
}

var (
	reads   = cmdKind{Kind: kindRead}
	changes = cmdKind{Kind: kindChange}
)

func dependsOn(why string) cmdKind { return cmdKind{Kind: kindDepends, Note: why} }

const (
	unlessReadOnly = "changes things unless --read-only says the command only reads (the policy checks it either way)"
	unlessWrite    = "only reads unless --write"
	bySubcommand   = "decided by the docker subcommand: ps/logs/inspect read, up/down/rm change"
	localProgram   = "decided by the program it starts on this computer"
	shellNote      = "an shellNote shell for a person: whatever they type"
)

// commandKinds is keyed by the command's (type, area, verb) (risk_keys.go).
var commandKinds = map[safetyKey]cmdKind{
	{"audit", "", "list"}:  reads,
	{"audit", "", "check"}: reads,

	{"cache", "", ""}:       reads,
	{"cache", "", "get"}:    reads,
	{"cache", "", "info"}:   reads,
	{"cache", "", "keys"}:   reads,
	{"cache", "", "rm"}:     changes,
	{"cache", "", "raw"}:    dependsOn(unlessWrite),
	{"cache", "", "edit"}:   changes,
	{"cache", "", "list"}:   reads,
	{"cache", "", "remove"}: changes,
	{"cache", "", "rename"}: changes,
	{"cache", "", "show"}:   reads,
	{"cache", "", "test"}:   reads,
	{"cache", "", "set"}:    changes,

	{"queue", "", ""}:              reads,
	{"queue", "topic", "create"}:   changes,
	{"queue", "topic", "show"}:     reads,
	{"queue", "consumer", "list"}:  reads,
	{"queue", "", "info"}:          reads,
	{"queue", "consumer", "show"}:  reads,
	{"queue", "topic", "list"}:     reads,
	{"queue", "message", "list"}:   reads,
	{"queue", "message", "delete"}: changes,
	{"queue", "topic", "delete"}:   changes,
	{"queue", "message", "create"}: changes,

	{"cert", "", ""}:      reads,
	{"cert", "", "check"}: reads,

	{"cluster", "", ""}:            reads,
	{"cluster", "", "apply"}:       changes,
	{"cluster", "", "deploy"}:      changes,
	{"cluster", "", "describe"}:    reads,
	{"cluster", "", "events"}:      reads,
	{"cluster", "", "exec"}:        dependsOn(unlessReadOnly),
	{"cluster", "tunnel", "start"}: changes, // hands out access (OD-13)
	{"cluster", "", "get"}:         reads,
	{"cluster", "helm", ""}:        reads,
	{"cluster", "helm", "history"}: reads,
	{"cluster", "helm", "list"}:    reads,
	{"cluster", "helm", "status"}:  reads,
	{"cluster", "helm", "values"}:  reads,
	{"cluster", "", "history"}:     reads,
	{"cluster", "", "logs"}:        reads,
	{"cluster", "", "list"}:        reads,
	{"cluster", "", "restart"}:     changes,
	{"cluster", "", "rm"}:          changes,
	{"cluster", "", "rollback"}:    changes,
	{"cluster", "", "raw"}:         dependsOn(unlessWrite),
	{"cluster", "", "scale"}:       changes,
	{"cluster", "", "shell"}:       dependsOn(shellNote),
	{"cluster", "", "status"}:      reads,

	{"config", "", ""}:              reads,
	{"config", "", "approval-code"}: changes,
	{"config", "", "get"}:           reads,
	{"config", "", "set"}:           changes,
	{"config", "", "show"}:          reads,

	{"conn", "", ""}:        reads,
	{"conn", "", "add"}:     changes,
	{"database", "", "add"}: changes,
	{"cache", "", "add"}:    changes,
	{"queue", "", "add"}:    changes,
	{"storage", "", "add"}:  changes,
	{"cluster", "", "add"}:  changes,
	{"registry", "", "add"}: changes,
	{"conn", "", "edit"}:    changes,
	{"conn", "", "kinds"}:   reads,
	{"conn", "", "list"}:    reads,
	{"conn", "", "rename"}:  changes,
	{"conn", "", "remove"}:  changes,
	{"conn", "", "show"}:    reads,
	{"conn", "", "test"}:    reads,

	{"", "cp", "copy"}: dependsOn("changes the destination: a server or bucket when it is the DST, only this computer when it is the SRC"),

	{"host", "cron", ""}:     reads,
	{"host", "cron", "list"}: reads,
	{"host", "cron", "rm"}:   changes,
	{"host", "cron", "set"}:  changes,

	{"database", "", ""}:           reads,
	{"database", "", "activity"}:   reads,
	{"database", "", "backup"}:     reads,
	{"database", "", "explain"}:    dependsOn("only plans the query; --analyze runs it, and a write needs --write too"),
	{"database", "", "grant"}:      changes,
	{"database", "user", "show"}:   reads,
	{"database", "", "info"}:       reads,
	{"database", "", "kill"}:       changes,
	{"database", "", "locks"}:      reads,
	{"database", "", "query"}:      dependsOn(unlessWrite),
	{"database", "", "restore"}:    changes,
	{"database", "", "revoke"}:     changes,
	{"database", "", "schema"}:     reads,
	{"database", "", "shell"}:      dependsOn(shellNote + "; read-only unless --write"),
	{"database", "", "sizes"}:      reads,
	{"database", "user", ""}:       reads,
	{"database", "user", "add"}:    changes,
	{"database", "user", "list"}:   reads,
	{"database", "user", "passwd"}: changes,
	{"database", "user", "rm"}:     changes,

	{"host", "docker", ""}:        reads,
	{"host", "docker", "compose"}: dependsOn(bySubcommand),
	{"host", "docker", "exec"}:    dependsOn(unlessReadOnly),
	{"host", "docker", "images"}:  reads,
	{"host", "docker", "inspect"}: reads,
	{"host", "docker", "logs"}:    reads,
	{"host", "docker", "prune"}:   changes,
	{"host", "docker", "ps"}:      reads,
	{"host", "docker", "pull"}:    changes,
	{"host", "docker", "raw"}:     dependsOn(bySubcommand),
	{"host", "docker", "restart"}: changes,
	{"host", "docker", "rm"}:      changes,
	{"host", "docker", "start"}:   changes,
	{"host", "docker", "stats"}:   reads,
	{"host", "docker", "stop"}:    changes,

	{"", "", "doctor"}:       reads,
	{"", "download", "copy"}: reads,
	{"host", "", "exec"}:     dependsOn(unlessReadOnly),
	{"", "", "export"}:       reads,
	{"host", "", "info"}:     reads,

	{"host", "file", ""}:        reads,
	{"host", "file", "cat"}:     reads,
	{"host", "file", "chmod"}:   changes,
	{"host", "file", "list"}:    reads,
	{"host", "file", "mkdir"}:   changes,
	{"host", "file", "mv"}:      changes,
	{"host", "file", "replace"}: changes,
	{"host", "file", "restore"}: changes,
	{"host", "file", "rm"}:      changes,
	{"host", "file", "stat"}:    reads,
	{"host", "file", "write"}:   changes,

	{"group", "", ""}:       reads,
	{"group", "", "create"}: changes,
	{"group", "", "list"}:   reads,
	{"group", "", "rename"}: changes,
	{"group", "", "remove"}: changes,

	{"agent", "", ""}:               reads,
	{"agent", "skill", "install"}:   changes,
	{"agent", "skill", "uninstall"}: changes,

	{"host", "", ""}:                        reads,
	{"host", "", "add"}:                     changes,
	{"credential", "certificate", ""}:       reads,
	{"credential", "certificate", "add"}:    changes,
	{"credential", "certificate", "list"}:   reads,
	{"credential", "certificate", "revoke"}: changes,
	{"credential", "certificate", "remove"}: changes,
	{"host", "", "edit"}:                    changes,
	{"host", "", "list"}:                    reads,
	{"host", "", "rename"}:                  changes,
	{"host", "", "remove"}:                  changes,
	{"host", "", "show"}:                    reads,
	{"host", "", "ssh-command"}:             reads,
	{"host", "", "test"}:                    reads,
	{"host", "", "trust"}:                   changes,

	{"", "", "import"}: changes,

	{"credential", "key", ""}:          reads,
	{"credential", "key", "add"}:       changes,
	{"credential", "key", "install"}:   changes,
	{"credential", "key", "edit"}:      changes,
	{"credential", "key", "create"}:    changes,
	{"credential", "key", "list"}:      reads,
	{"credential", "key", "rename"}:    changes,
	{"credential", "key", "uninstall"}: changes,
	{"credential", "key", "remove"}:    changes,
	{"credential", "key", "show"}:      reads,

	{"", "", "list"}:      reads,
	{"", "", "login"}:     changes,
	{"login", "", "aws"}:  changes,
	{"", "", "logout"}:    changes,
	{"logout", "", "aws"}: changes,
	{"host", "", "logs"}:  reads,

	{"host", "network", ""}:      reads,
	{"host", "network", "check"}: reads,
	{"host", "network", "dns"}:   reads,
	{"host", "network", "http"}:  reads,
	{"host", "network", "ports"}: reads,

	{"host", "package", ""}:           reads,
	{"host", "package", "install"}:    changes,
	{"host", "package", "installed"}:  reads,
	{"host", "package", "rm"}:         changes,
	{"host", "package", "security"}:   dependsOn("only reads, unless --refresh updates the package index first"),
	{"host", "package", "update"}:     changes,
	{"host", "package", "upgradable"}: dependsOn("only reads, unless --refresh updates the package index first"),
	{"host", "package", "upgrade"}:    changes,

	{"policy", "", ""}:       reads,
	{"policy", "", "remove"}: changes,
	{"policy", "", "check"}:  reads,
	{"policy", "", "create"}: changes,
	{"policy", "", "list"}:   reads,
	{"policy", "", "edit"}:   changes,
	{"policy", "", "show"}:   reads,

	{"host", "", "restart"}: changes,

	{"", "", "rename"}: changes,

	{"snippet", "", ""}:       reads,
	{"snippet", "", "create"}: changes,
	{"snippet", "", "list"}:   reads,
	{"snippet", "", "remove"}: changes,
	{"snippet", "", "exec"}:   dependsOn("decided by the recipe's command, like exec"),

	{"registry", "", ""}:            reads,
	{"registry", "", "edit"}:        changes,
	{"registry", "", "list"}:        reads,
	{"registry", "", "remove"}:      changes,
	{"registry", "", "rename"}:      changes,
	{"registry", "", "show"}:        reads,
	{"registry", "", "test"}:        reads,
	{"registry", "image", ""}:       reads,
	{"registry", "image", "copy"}:   changes,
	{"registry", "image", "show"}:   reads,
	{"registry", "image", "list"}:   reads,
	{"registry", "image", "prune"}:  changes,
	{"registry", "image", "delete"}: changes,

	{"", "", "schema"}: reads,

	{"credential", "", ""}:            reads,
	{"credential", "", "run"}:         dependsOn(localProgram),
	{"credential", "", "check"}:       reads,
	{"credential", "", "cp"}:          changes,
	{"credential", "", "show"}:        reads,
	{"config", "vault", "keychain"}:   changes,
	{"credential", "", "list"}:        reads,
	{"credential", "", "rename"}:      changes,
	{"config", "vault", "passphrase"}: changes,
	{"credential", "", "remove"}:      changes,
	{"credential", "", "add"}:         changes,

	{"host", "", "shell"}: dependsOn(shellNote),

	{"", "", "ssh-gate"}:       dependsOn("runs the komando command an SSH key sent, when ssh-gate allows it"),
	{"ssh-gate", "", "line"}:   reads,
	{"ssh-gate", "", "status"}: reads,

	{"", "", "status"}: reads,

	{"storage", "", ""}:               reads,
	{"storage", "object", "read"}:     reads,
	{"storage", "object", "chmod"}:    changes,
	{"storage", "object", "download"}: reads,
	{"storage", "object", "link"}:     changes, // hands out access (OD-13)
	{"storage", "object", "list"}:     reads,
	{"storage", "object", "create"}:   changes,
	{"storage", "object", "move"}:     changes,
	{"storage", "object", "delete"}:   changes,
	{"storage", "object", "upload"}:   changes,

	{"host", "service", ""}:              reads,
	{"host", "service", "daemon-reload"}: changes,
	{"host", "service", "disable"}:       changes,
	{"host", "service", "enable"}:        changes,
	{"host", "service", "list"}:          reads,
	{"host", "service", "logs"}:          reads,
	{"host", "service", "reload"}:        changes,
	{"host", "service", "restart"}:       changes,
	{"host", "service", "start"}:         changes,
	{"host", "service", "status"}:        reads,
	{"host", "service", "stop"}:          changes,

	{"", "sync", "copy"}: changes,
	{"", "", "test"}:     reads,

	{"host", "tunnel", ""}:      reads,
	{"host", "tunnel", "list"}:  reads,
	{"host", "tunnel", "start"}: changes,
	{"host", "tunnel", "stop"}:  changes,

	{"", "upload", "copy"}: changes,

	{"host", "user", ""}:       reads,
	{"host", "user", "add"}:    changes,
	{"host", "user", "list"}:   reads,
	{"host", "user", "lock"}:   changes,
	{"host", "user", "rm"}:     changes,
	{"host", "user", "unlock"}: changes,

	{"", "", "update"}:  changes,
	{"", "", "version"}: reads,

	{"vpn", "", ""}:       reads,
	{"vpn", "", "add"}:    changes,
	{"vpn", "", "stop"}:   changes,
	{"vpn", "", "edit"}:   changes,
	{"vpn", "", "list"}:   reads,
	{"vpn", "", "rename"}: changes,
	{"vpn", "", "remove"}: changes,
	{"vpn", "", "show"}:   reads,
	{"vpn", "", "status"}: reads,
	{"vpn", "", "test"}:   reads,
	{"vpn", "", "start"}:  changes,
}

// kindOf is the kind of a command; ok is false for one missing from the table.
func kindOf(c *cobra.Command) (cmdKind, bool) {
	key, ok := cmdKeys[cmdID(c)]
	if !ok {
		return cmdKind{}, false
	}
	k, ok := commandKinds[key]
	return k, ok
}

// commandKey is c's path without the leading "komando ".
func commandKey(c *cobra.Command) string {
	p := c.CommandPath()
	if r := c.Root(); r != nil && r != c {
		p = p[len(r.Name())+1:]
	}
	return p
}
