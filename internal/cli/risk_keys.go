package cli

// The safety tables key a command by where it sits in the v2.7 grammar
// (TYPE PROVIDER AREA VERB, spec section 7.1), not by its path: a
// provider adds a row only when it differs. Until the paths move, cmdKeys
// gives each of today's command IDs its key.
//
// Where v2.7 has a home for a command, the key is that home without the
// provider (queue.purge is queue message delete). Where v2.7 replaces a
// command by exec, raw or query, or removes it, the key keeps today's
// words under the v2.7 type (fs.rm is host file rm), so no two of today's
// commands share a key and every row keeps the commands it had.
// TestSafetyKeys checks that every command has a key and every key one
// command.

// safetyKey is a command's place: its type (or komando's own noun; ""
// for a top-level action), the area inside it ("" for none) and its verb
// ("" for a group).
type safetyKey struct{ typ, area, verb string }

// cmdKeys is each command ID's key.
var cmdKeys = map[string]safetyKey{
	// top-level actions and built-ins
	"komando": {"", "", "komando"}, "list": {"", "", "list"}, "test": {"", "", "test"}, "status": {"", "", "status"},
	"doctor": {"", "", "doctor"}, "import": {"", "", "import"}, "export": {"", "", "export"},
	"update": {"", "", "update"}, "version": {"", "", "version"}, "schema": {"", "", "schema"},
	"cp": {"", "cp", "copy"}, "upload": {"", "upload", "copy"}, "download": {"", "download", "copy"}, "sync": {"", "sync", "copy"},
	// removed in v2.7: help topics, cobra's own commands, login, ssh-gate, rename
	"help": {"", "", "help"}, "environment": {"", "", "environment"}, "exit-codes": {"", "", "exit-codes"},
	"output": {"", "", "output"}, "safety": {"", "", "safety"}, "rename": {"", "", "rename"},
	"completion": {"", "", "completion"}, "completion.bash": {"completion", "", "bash"}, "completion.fish": {"completion", "", "fish"},
	"completion.powershell": {"completion", "", "powershell"}, "completion.zsh": {"completion", "", "zsh"},
	"login": {"", "", "login"}, "login.aws": {"login", "", "aws"}, "login.azure": {"login", "", "azure"}, "login.gcp": {"login", "", "gcp"},
	"login-holder": {"", "", "login-holder"}, "logout": {"", "", "logout"}, "logout.aws": {"logout", "", "aws"},
	"ssh-gate": {"", "", "ssh-gate"}, "ssh-gate.line": {"ssh-gate", "", "line"}, "ssh-gate.status": {"ssh-gate", "", "status"},
	"cert": {"cert", "", ""}, "cert.check": {"cert", "", "check"},

	// host
	"host": {"host", "", ""}, "host.add": {"host", "", "add"}, "host.edit": {"host", "", "edit"}, "host.list": {"host", "", "list"},
	"host.rename": {"host", "", "rename"}, "host.rm": {"host", "", "remove"}, "host.show": {"host", "", "show"},
	"host.test": {"host", "", "test"}, "host.trust": {"host", "", "trust"}, "host.ssh-command": {"host", "", "ssh-command"},
	"exec": {"host", "", "exec"}, "shell": {"host", "", "shell"}, "logs": {"host", "", "logs"}, "facts": {"host", "", "info"},
	"reboot": {"host", "", "restart"},
	"tunnel": {"host", "tunnel", ""}, "tunnel.list": {"host", "tunnel", "list"}, "tunnel.start": {"host", "tunnel", "start"},
	"tunnel.stop": {"host", "tunnel", "stop"}, "tunnel.serve": {"host", "tunnel", "serve"},
	"fs": {"host", "file", ""}, "fs.cat": {"host", "file", "cat"}, "fs.chmod": {"host", "file", "chmod"}, "fs.list": {"host", "file", "list"},
	"fs.mkdir": {"host", "file", "mkdir"}, "fs.mv": {"host", "file", "mv"}, "fs.replace": {"host", "file", "replace"},
	"fs.restore": {"host", "file", "restore"}, "fs.rm": {"host", "file", "rm"}, "fs.stat": {"host", "file", "stat"}, "fs.write": {"host", "file", "write"},
	"svc": {"host", "service", ""}, "svc.daemon-reload": {"host", "service", "daemon-reload"}, "svc.disable": {"host", "service", "disable"},
	"svc.enable": {"host", "service", "enable"}, "svc.list": {"host", "service", "list"}, "svc.logs": {"host", "service", "logs"},
	"svc.reload": {"host", "service", "reload"}, "svc.restart": {"host", "service", "restart"}, "svc.start": {"host", "service", "start"},
	"svc.status": {"host", "service", "status"}, "svc.stop": {"host", "service", "stop"},
	"pkg": {"host", "package", ""}, "pkg.install": {"host", "package", "install"}, "pkg.installed": {"host", "package", "installed"},
	"pkg.rm": {"host", "package", "rm"}, "pkg.security": {"host", "package", "security"}, "pkg.update": {"host", "package", "update"},
	"pkg.upgradable": {"host", "package", "upgradable"}, "pkg.upgrade": {"host", "package", "upgrade"},
	"net": {"host", "network", ""}, "net.check": {"host", "network", "check"}, "net.dns": {"host", "network", "dns"},
	"net.http": {"host", "network", "http"}, "net.ports": {"host", "network", "ports"},
	"cron": {"host", "cron", ""}, "cron.list": {"host", "cron", "list"}, "cron.rm": {"host", "cron", "rm"}, "cron.set": {"host", "cron", "set"},
	"user": {"host", "user", ""}, "user.add": {"host", "user", "add"}, "user.list": {"host", "user", "list"}, "user.lock": {"host", "user", "lock"},
	"user.rm": {"host", "user", "rm"}, "user.unlock": {"host", "user", "unlock"},
	"job": {"host", "job", ""}, "job.kill": {"host", "job", "kill"}, "job.list": {"host", "job", "list"}, "job.logs": {"host", "job", "logs"},
	"job.rm": {"host", "job", "rm"}, "job.start": {"host", "job", "start"}, "job.status": {"host", "job", "status"}, "job.wait": {"host", "job", "wait"},
	"docker": {"host", "docker", ""}, "docker.compose": {"host", "docker", "compose"}, "docker.exec": {"host", "docker", "exec"},
	"docker.images": {"host", "docker", "images"}, "docker.inspect": {"host", "docker", "inspect"}, "docker.logs": {"host", "docker", "logs"},
	"docker.prune": {"host", "docker", "prune"}, "docker.ps": {"host", "docker", "ps"}, "docker.pull": {"host", "docker", "pull"},
	"docker.raw": {"host", "docker", "raw"}, "docker.restart": {"host", "docker", "restart"}, "docker.rm": {"host", "docker", "rm"},
	"docker.start": {"host", "docker", "start"}, "docker.stats": {"host", "docker", "stats"}, "docker.stop": {"host", "docker", "stop"},

	// database
	"db": {"database", "", ""}, "db.add": {"database", "", "add"}, "db.dump": {"database", "", "backup"}, "db.restore": {"database", "", "restore"},
	"db.query": {"database", "", "query"}, "db.shell": {"database", "", "shell"},
	"db.activity": {"database", "", "activity"}, "db.explain": {"database", "", "explain"}, "db.grant": {"database", "", "grant"},
	"db.info": {"database", "", "info"}, "db.kill": {"database", "", "kill"}, "db.locks": {"database", "", "locks"},
	"db.revoke": {"database", "", "revoke"}, "db.schema": {"database", "", "schema"}, "db.sizes": {"database", "", "sizes"},
	"db.user": {"database", "user", ""}, "db.user.add": {"database", "user", "add"}, "db.user.list": {"database", "user", "list"},
	"db.user.passwd": {"database", "user", "passwd"}, "db.user.rm": {"database", "user", "rm"}, "db.user.show": {"database", "user", "show"},

	// cache
	"cache": {"cache", "", ""}, "cache.add": {"cache", "", "add"}, "cache.run": {"cache", "", "raw"},
	"cache.get": {"cache", "", "get"}, "cache.info": {"cache", "", "info"}, "cache.keys": {"cache", "", "keys"},
	"cache.rm": {"cache", "", "rm"}, "cache.set": {"cache", "", "set"},

	// queue
	"queue": {"queue", "", ""}, "queue.add": {"queue", "", "add"}, "queue.info": {"queue", "", "info"},
	"queue.create": {"queue", "topic", "create"}, "queue.describe": {"queue", "topic", "show"}, "queue.list": {"queue", "topic", "list"},
	"queue.rm": {"queue", "topic", "delete"}, "queue.groups": {"queue", "consumer", "list"}, "queue.lag": {"queue", "consumer", "show"},
	"queue.peek": {"queue", "message", "list"}, "queue.purge": {"queue", "message", "delete"}, "queue.send": {"queue", "message", "create"},

	// storage
	"storage": {"storage", "", ""}, "storage.add": {"storage", "", "add"},
	"storage.cat": {"storage", "object", "read"}, "storage.chmod": {"storage", "object", "chmod"}, "storage.link": {"storage", "object", "link"},
	"storage.list": {"storage", "object", "list"}, "storage.mkdir": {"storage", "object", "create"}, "storage.mv": {"storage", "object", "move"},
	"storage.rm": {"storage", "object", "delete"}, "storage.download": {"storage", "object", "download"}, "storage.upload": {"storage", "object", "upload"},

	// cluster
	"cluster": {"cluster", "", ""}, "cluster.add": {"cluster", "", "add"}, "cluster.exec": {"cluster", "", "exec"},
	"cluster.run": {"cluster", "", "raw"}, "cluster.shell": {"cluster", "", "shell"}, "cluster.forward": {"cluster", "tunnel", "start"},
	"cluster.apply": {"cluster", "", "apply"}, "cluster.deploy": {"cluster", "", "deploy"}, "cluster.describe": {"cluster", "", "describe"},
	"cluster.events": {"cluster", "", "events"}, "cluster.get": {"cluster", "", "get"}, "cluster.history": {"cluster", "", "history"},
	"cluster.list": {"cluster", "", "list"}, "cluster.logs": {"cluster", "", "logs"}, "cluster.restart": {"cluster", "", "restart"},
	"cluster.rm": {"cluster", "", "rm"}, "cluster.rollback": {"cluster", "", "rollback"}, "cluster.scale": {"cluster", "", "scale"},
	"cluster.status": {"cluster", "", "status"},
	"cluster.helm":   {"cluster", "helm", ""}, "cluster.helm.history": {"cluster", "helm", "history"}, "cluster.helm.list": {"cluster", "helm", "list"},
	"cluster.helm.status": {"cluster", "helm", "status"}, "cluster.helm.values": {"cluster", "helm", "values"},

	// registry
	"registry": {"registry", "", ""}, "registry.add": {"registry", "", "add"},
	"registry.copy": {"registry", "image", "copy"}, "registry.inspect": {"registry", "image", "show"}, "registry.list": {"registry", "image", "list"},
	"registry.prune": {"registry", "image", "prune"}, "registry.rm": {"registry", "image", "delete"},

	// vpn
	"vpn": {"vpn", "", ""}, "vpn.add": {"vpn", "", "add"}, "vpn.edit": {"vpn", "", "edit"}, "vpn.list": {"vpn", "", "list"},
	"vpn.rename": {"vpn", "", "rename"}, "vpn.rm": {"vpn", "", "remove"}, "vpn.show": {"vpn", "", "show"}, "vpn.test": {"vpn", "", "test"},
	"vpn.status": {"vpn", "", "status"}, "vpn.up": {"vpn", "", "start"}, "vpn.down": {"vpn", "", "stop"}, "vpn.serve": {"vpn", "", "serve"},

	// conn: in v2.7 each entry lives under its type and provider
	"conn": {"conn", "", ""}, "conn.add": {"conn", "", "add"}, "conn.edit": {"conn", "", "edit"}, "conn.kinds": {"conn", "", "kinds"},
	"conn.list": {"conn", "", "list"}, "conn.rename": {"conn", "", "rename"}, "conn.rm": {"conn", "", "remove"},
	"conn.show": {"conn", "", "show"}, "conn.test": {"conn", "", "test"},

	// credential: secret, key and host CAs
	"secret": {"credential", "", ""}, "secret.list": {"credential", "", "list"}, "secret.set": {"credential", "", "add"},
	"secret.show": {"credential", "", "show"}, "secret.rename": {"credential", "", "rename"}, "secret.rm": {"credential", "", "remove"},
	"secret.run": {"credential", "", "run"}, "secret.check": {"credential", "", "check"}, "secret.cp": {"credential", "", "cp"},
	"key": {"credential", "key", ""}, "key.add": {"credential", "key", "add"}, "key.deploy": {"credential", "key", "install"},
	"key.edit": {"credential", "key", "edit"}, "key.gen": {"credential", "key", "create"}, "key.list": {"credential", "key", "list"},
	"key.rename": {"credential", "key", "rename"}, "key.revoke": {"credential", "key", "uninstall"}, "key.rm": {"credential", "key", "remove"},
	"key.show": {"credential", "key", "show"},
	"host.ca":  {"credential", "certificate", ""}, "host.ca.add": {"credential", "certificate", "add"},
	"host.ca.list": {"credential", "certificate", "list"}, "host.ca.rm": {"credential", "certificate", "remove"},
	"host.ca.revoke": {"credential", "certificate", "revoke"},

	// komando's own nouns
	"group": {"group", "", ""}, "group.add": {"group", "", "create"}, "group.list": {"group", "", "list"},
	"group.rename": {"group", "", "rename"}, "group.rm": {"group", "", "remove"},
	"recipe": {"snippet", "", ""}, "recipe.add": {"snippet", "", "create"}, "recipe.list": {"snippet", "", "list"},
	"recipe.rm": {"snippet", "", "remove"}, "recipe.run": {"snippet", "", "exec"},
	"policy": {"policy", "", ""}, "policy.check": {"policy", "", "check"}, "policy.deny": {"policy", "", "create"},
	"policy.list": {"policy", "", "list"}, "policy.rm": {"policy", "", "remove"},
	"config": {"config", "", ""}, "config.approval-code": {"config", "", "approval-code"}, "config.get": {"config", "", "get"},
	"config.set": {"config", "", "set"}, "config.show": {"config", "", "show"},
	"secret.keychain": {"config", "vault", "keychain"}, "secret.passphrase": {"config", "vault", "passphrase"},
	"guide": {"agent", "", ""}, "guide.guard": {"agent", "", "guard"},
	"guide.install": {"agent", "skill", "install"}, "guide.uninstall": {"agent", "skill", "uninstall"},
	"audit": {"audit", "", "list"}, "audit.verify": {"audit", "", "check"},
}

// keyIDs is cmdKeys turned round: the command ID each key names.
var keyIDs = func() map[safetyKey]string {
	m := make(map[safetyKey]string, len(cmdKeys))
	for id, k := range cmdKeys {
		m[k] = id
	}
	return m
}()
