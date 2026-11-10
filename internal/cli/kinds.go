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
// checks). The safety checks themselves (guard, guardConns,
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
	shellNote      = "an shellNote shell for a person: whatever they type"
)

// commandKinds is keyed by the command path without "komando ".
var commandKinds = map[string]cmdKind{
	"audit":        reads,
	"audit verify": reads,

	"cache":      reads,
	"cache get":  reads,
	"cache info": reads,
	"cache keys": reads,
	"cache rm":   changes,
	"cache run":  dependsOn(unlessWrite),
	"cache set":  changes,

	"queue":          reads,
	"queue create":   changes,
	"queue describe": reads,
	"queue groups":   reads,
	"queue info":     reads,
	"queue lag":      reads,
	"queue ls":       reads,
	"queue peek":     reads,
	"queue purge":    changes,
	"queue rm":       changes,
	"queue send":     changes,

	"cert":       reads,
	"cert check": reads,

	"cluster":              reads,
	"cluster apply":        changes,
	"cluster deploy":       changes,
	"cluster describe":     reads,
	"cluster events":       reads,
	"cluster exec":         dependsOn(unlessReadOnly),
	"cluster forward":      reads,
	"cluster get":          reads,
	"cluster helm":         reads,
	"cluster helm history": reads,
	"cluster helm ls":      reads,
	"cluster helm status":  reads,
	"cluster helm values":  reads,
	"cluster history":      reads,
	"cluster logs":         reads,
	"cluster ls":           reads,
	"cluster restart":      changes,
	"cluster rm":           changes,
	"cluster rollback":     changes,
	"cluster run":          dependsOn(unlessWrite),
	"cluster scale":        changes,
	"cluster shell":        dependsOn(shellNote),
	"cluster status":       reads,

	"config":               reads,
	"config approval-code": changes,
	"config get":           reads,
	"config set":           changes,
	"config show":          reads,

	"conn":         reads,
	"conn add":     changes,
	"db add":       changes,
	"cache add":    changes,
	"queue add":    changes,
	"storage add":  changes,
	"cluster add":  changes,
	"registry add": changes,
	"conn edit":    changes,
	"conn kinds":   reads,
	"conn list":    reads,
	"conn mv":      changes,
	"conn rm":      changes,
	"conn show":    reads,
	"conn test":    reads,

	"cp": dependsOn("changes the destination: a server or bucket when it is the DST, only this computer when it is the SRC"),

	"cron":      reads,
	"cron list": reads,
	"cron rm":   changes,
	"cron set":  changes,

	"db":             reads,
	"db activity":    reads,
	"db dump":        reads,
	"db explain":     dependsOn("only plans the query; --analyze runs it, and a write needs --write too"),
	"db grant":       changes,
	"db grants":      reads,
	"db info":        reads,
	"db kill":        changes,
	"db locks":       reads,
	"db query":       dependsOn(unlessWrite),
	"db restore":     changes,
	"db revoke":      changes,
	"db schema":      reads,
	"db shell":       dependsOn(shellNote + "; read-only unless --write"),
	"db sizes":       reads,
	"db user":        reads,
	"db user add":    changes,
	"db user ls":     reads,
	"db user passwd": changes,
	"db user rm":     changes,

	"docker":         reads,
	"docker compose": dependsOn(bySubcommand),
	"docker exec":    dependsOn(unlessReadOnly),
	"docker images":  reads,
	"docker inspect": reads,
	"docker logs":    reads,
	"docker prune":   changes,
	"docker ps":      reads,
	"docker pull":    changes,
	"docker raw":     dependsOn(bySubcommand),
	"docker restart": changes,
	"docker rm":      changes,
	"docker start":   changes,
	"docker stats":   reads,
	"docker stop":    changes,

	"doctor":   reads,
	"download": reads,
	"exec":     dependsOn(unlessReadOnly),
	"export":   reads,
	"facts":    reads,

	"fs":         reads,
	"fs cat":     reads,
	"fs chmod":   changes,
	"fs ls":      reads,
	"fs mkdir":   changes,
	"fs mv":      changes,
	"fs replace": changes,
	"fs restore": changes,
	"fs rm":      changes,
	"fs stat":    reads,
	"fs write":   changes,

	"group":      reads,
	"group add":  changes,
	"group list": reads,
	"group mv":   changes,
	"group rm":   changes,

	"guide":           reads,
	"guide install":   changes,
	"guide uninstall": changes,

	"host":             reads,
	"host add":         changes,
	"host edit":        changes,
	"host export":      reads,
	"host import":      changes,
	"host list":        reads,
	"host mv":          changes,
	"host rm":          changes,
	"host show":        reads,
	"host ssh-command": reads,
	"host test":        reads,
	"host trust":       changes,

	"import": changes,

	"job":        reads,
	"job kill":   changes,
	"job list":   reads,
	"job logs":   reads,
	"job rm":     changes,
	"job start":  dependsOn(unlessReadOnly),
	"job status": reads,
	"job wait":   reads,

	"key":        reads,
	"key add":    changes,
	"key deploy": changes,
	"key edit":   changes,
	"key gen":    changes,
	"key list":   reads,
	"key mv":     changes,
	"key revoke": changes,
	"key rm":     changes,
	"key show":   reads,

	"list":      reads,
	"login":     changes,
	"login aws": changes,
	"logout":    changes,
	"logs":      reads,

	"net":       reads,
	"net check": reads,
	"net dns":   reads,
	"net http":  reads,
	"net ports": reads,

	"pkg":            reads,
	"pkg install":    changes,
	"pkg installed":  reads,
	"pkg rm":         changes,
	"pkg security":   dependsOn("only lists unless --apply"),
	"pkg update":     changes,
	"pkg upgradable": dependsOn("only reads, unless --refresh updates the package index first"),
	"pkg upgrade":    changes,

	"policy":       reads,
	"policy rm":    changes,
	"policy check": reads,
	"policy deny":  changes,
	"policy list":  reads,

	"prompt": reads,
	"reboot": changes,

	"rename": changes,

	"recipe":      reads,
	"recipe add":  changes,
	"recipe list": reads,
	"recipe rm":   changes,
	"recipe run":  dependsOn("decided by the recipe's command, like exec"),

	"registry":         reads,
	"registry copy":    changes,
	"registry inspect": reads,
	"registry ls":      reads,
	"registry prune":   changes,
	"registry rm":      changes,

	"schema": reads,
	"script": dependsOn(unlessReadOnly),

	"secret":            reads,
	"secret check":      reads,
	"secret cp":         changes,
	"secret get":        reads,
	"secret keychain":   changes,
	"secret list":       reads,
	"secret mv":         changes,
	"secret passphrase": changes,
	"secret rm":         changes,
	"secret set":        changes,

	"shell": dependsOn(shellNote),

	"ssh-gate":      dependsOn("runs the komando command an SSH key sent, when ssh-gate allows it"),
	"ssh-gate line": reads,

	"status": reads,

	"storage":          reads,
	"storage cat":      reads,
	"storage download": reads,
	"storage link":     reads,
	"storage ls":       reads,
	"storage rm":       changes,
	"storage upload":   changes,

	"svc":               reads,
	"svc daemon-reload": changes,
	"svc disable":       changes,
	"svc enable":        changes,
	"svc list":          reads,
	"svc logs":          reads,
	"svc reload":        changes,
	"svc restart":       changes,
	"svc start":         changes,
	"svc status":        reads,
	"svc stop":          changes,

	"sync": changes,
	"test": reads,

	"tunnel":       reads,
	"tunnel list":  reads,
	"tunnel start": changes,
	"tunnel stop":  changes,

	"upload": changes,

	"user":        reads,
	"user add":    changes,
	"user list":   reads,
	"user lock":   changes,
	"user rm":     changes,
	"user unlock": changes,

	"update":  changes,
	"version": reads,

	"vpn":        reads,
	"vpn add":    changes,
	"vpn down":   changes,
	"vpn edit":   changes,
	"vpn list":   reads,
	"vpn mv":     changes,
	"vpn rm":     changes,
	"vpn show":   reads,
	"vpn status": reads,
	"vpn test":   reads,
	"vpn up":     changes,
}

// kindOf is the kind of a command; ok is false for one missing from the table.
func kindOf(c *cobra.Command) (cmdKind, bool) {
	k, ok := commandKinds[commandKey(c)]
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
