package capability

import "maps"

// TodayKey is the safety key of one command of today (pre-cut): where it
// sits in the v2.7 grammar without its provider. internal/cli keys its
// safety tables (tier rows, kinds, TARGET kinds) by it until the cut.
type TodayKey struct{ Type, Area, Verb string }

// TodayKeys returns the safety key of every command ID of today: the key of
// the leaf that keeps the ID under its own key (Leaf.Today), else the key
// todayOnlyKeys gives it. The map is new on each call.
func TodayKeys() map[string]TodayKey {
	keys := maps.Clone(todayOnlyKeys)
	for _, l := range leaves {
		for _, id := range l.Today {
			keys[id] = TodayKey{l.Type, l.Area, l.Verb}
		}
	}
	return keys
}

// todayOnlyKeys (pre-cut) are the keys no leaf gives: commands v2.7
// replaces by exec, raw or query, or removes, keep today's words under the
// v2.7 type (fs.rm is host file rm), so no two of today's commands share a
// key; one command that splits into kinds (secret.set) keeps the noun's key;
// a group of today has its area and no verb.
var todayOnlyKeys = map[string]TodayKey{
	// top-level actions and built-ins
	"komando": {"", "", "komando"}, "cp": {"", "cp", "copy"}, "upload": {"", "upload", "copy"}, "download": {"", "download", "copy"},
	"sync": {"", "sync", "copy"},
	// removed in v2.7: help topics, cobra's own commands, login, rename
	"help": {"", "", "help"}, "environment": {"", "", "environment"}, "exit-codes": {"", "", "exit-codes"}, "output": {"", "", "output"},
	"safety": {"", "", "safety"}, "rename": {"", "", "rename"}, "completion": {"", "", "completion"}, "completion.bash": {"completion", "", "bash"},
	"completion.fish": {"completion", "", "fish"}, "completion.powershell": {"completion", "", "powershell"}, "completion.zsh": {"completion", "", "zsh"}, "login": {"", "", "login"},
	"login.aws": {"login", "", "aws"}, "login.azure": {"login", "", "azure"}, "login.gcp": {"login", "", "gcp"}, "login-holder": {"", "", "login-holder"},
	"logout": {"", "", "logout"}, "logout.aws": {"logout", "", "aws"}, "cert": {"cert", "", ""}, "cert.check": {"cert", "", "check"},

	// host
	"host": {"host", "", ""}, "host.ssh-command": {"host", "", "ssh-command"}, "logs": {"host", "", "logs"}, "facts": {"host", "", "info"},
	"reboot": {"host", "", "restart"}, "tunnel": {"host", "tunnel", ""}, "tunnel.serve": {"host", "tunnel", "serve"}, "fs": {"host", "file", ""},
	"fs.cat": {"host", "file", "cat"}, "fs.chmod": {"host", "file", "chmod"}, "fs.list": {"host", "file", "list"}, "fs.mkdir": {"host", "file", "mkdir"},
	"fs.mv": {"host", "file", "mv"}, "fs.replace": {"host", "file", "replace"}, "fs.restore": {"host", "file", "restore"}, "fs.rm": {"host", "file", "rm"},
	"fs.stat": {"host", "file", "stat"}, "fs.write": {"host", "file", "write"}, "svc": {"host", "service", ""}, "svc.daemon-reload": {"host", "service", "daemon-reload"},
	"svc.disable": {"host", "service", "disable"}, "svc.enable": {"host", "service", "enable"}, "svc.list": {"host", "service", "list"}, "svc.logs": {"host", "service", "logs"},
	"svc.reload": {"host", "service", "reload"}, "svc.restart": {"host", "service", "restart"}, "svc.start": {"host", "service", "start"}, "svc.status": {"host", "service", "status"},
	"svc.stop": {"host", "service", "stop"}, "pkg": {"host", "package", ""}, "pkg.install": {"host", "package", "install"}, "pkg.installed": {"host", "package", "installed"},
	"pkg.rm": {"host", "package", "rm"}, "pkg.security": {"host", "package", "security"}, "pkg.update": {"host", "package", "update"}, "pkg.upgradable": {"host", "package", "upgradable"},
	"pkg.upgrade": {"host", "package", "upgrade"}, "net": {"host", "network", ""}, "net.check": {"host", "network", "check"}, "net.dns": {"host", "network", "dns"},
	"net.http": {"host", "network", "http"}, "net.ports": {"host", "network", "ports"}, "cron": {"host", "cron", ""}, "cron.list": {"host", "cron", "list"},
	"cron.rm": {"host", "cron", "rm"}, "cron.set": {"host", "cron", "set"}, "user": {"host", "user", ""}, "user.add": {"host", "user", "add"},
	"user.list": {"host", "user", "list"}, "user.lock": {"host", "user", "lock"}, "user.rm": {"host", "user", "rm"}, "user.unlock": {"host", "user", "unlock"},
	"job": {"host", "job", ""}, "job.kill": {"host", "job", "kill"}, "job.list": {"host", "job", "list"}, "job.logs": {"host", "job", "logs"},
	"job.rm": {"host", "job", "rm"}, "job.start": {"host", "job", "start"}, "job.status": {"host", "job", "status"}, "job.wait": {"host", "job", "wait"},
	"docker": {"host", "docker", ""}, "docker.compose": {"host", "docker", "compose"}, "docker.exec": {"host", "docker", "exec"}, "docker.images": {"host", "docker", "images"},
	"docker.inspect": {"host", "docker", "inspect"}, "docker.logs": {"host", "docker", "logs"}, "docker.prune": {"host", "docker", "prune"}, "docker.ps": {"host", "docker", "ps"},
	"docker.pull": {"host", "docker", "pull"}, "docker.raw": {"host", "docker", "raw"}, "docker.restart": {"host", "docker", "restart"}, "docker.rm": {"host", "docker", "rm"},
	"docker.start": {"host", "docker", "start"}, "docker.stats": {"host", "docker", "stats"}, "docker.stop": {"host", "docker", "stop"},

	// database
	"db": {"database", "", ""}, "db.activity": {"database", "", "activity"}, "db.explain": {"database", "", "explain"}, "db.grant": {"database", "", "grant"},
	"db.info": {"database", "", "info"}, "db.kill": {"database", "", "kill"}, "db.locks": {"database", "", "locks"}, "db.revoke": {"database", "", "revoke"},
	"db.schema": {"database", "", "schema"}, "db.sizes": {"database", "", "sizes"}, "db.user": {"database", "user", ""}, "db.user.add": {"database", "user", "add"},
	"db.user.list": {"database", "user", "list"}, "db.user.passwd": {"database", "user", "passwd"}, "db.user.rm": {"database", "user", "rm"}, "db.user.show": {"database", "user", "show"},

	// cache
	"cache": {"cache", "", ""}, "cache.get": {"cache", "", "get"}, "cache.info": {"cache", "", "info"}, "cache.keys": {"cache", "", "keys"},
	"cache.rm": {"cache", "", "rm"}, "cache.set": {"cache", "", "set"},

	// queue
	"queue": {"queue", "", ""},

	// storage
	"storage": {"storage", "", ""}, "storage.chmod": {"storage", "object", "chmod"}, "storage.download": {"storage", "object", "download"}, "storage.upload": {"storage", "object", "upload"},

	// cluster
	"cluster": {"cluster", "", ""}, "cluster.apply": {"cluster", "", "apply"}, "cluster.deploy": {"cluster", "", "deploy"}, "cluster.describe": {"cluster", "", "describe"},
	"cluster.events": {"cluster", "", "events"}, "cluster.get": {"cluster", "", "get"}, "cluster.history": {"cluster", "", "history"}, "cluster.list": {"cluster", "", "list"},
	"cluster.logs": {"cluster", "", "logs"}, "cluster.restart": {"cluster", "", "restart"}, "cluster.rm": {"cluster", "", "rm"}, "cluster.rollback": {"cluster", "", "rollback"},
	"cluster.scale": {"cluster", "", "scale"}, "cluster.status": {"cluster", "", "status"}, "cluster.helm": {"cluster", "helm", ""}, "cluster.helm.history": {"cluster", "helm", "history"},
	"cluster.helm.list": {"cluster", "helm", "list"}, "cluster.helm.status": {"cluster", "helm", "status"}, "cluster.helm.values": {"cluster", "helm", "values"},

	// registry
	"registry": {"registry", "", ""},

	// vpn
	"vpn": {"vpn", "", ""}, "vpn.serve": {"vpn", "", "serve"},

	// conn: in v2.7 each entry lives under its type and provider
	"conn": {"conn", "", ""}, "conn.add": {"conn", "", "add"}, "conn.edit": {"conn", "", "edit"}, "conn.kinds": {"conn", "", "kinds"},
	"conn.list": {"conn", "", "list"}, "conn.rename": {"conn", "", "rename"}, "conn.rm": {"conn", "", "remove"}, "conn.show": {"conn", "", "show"},
	"conn.test": {"conn", "", "test"},

	// credential: secret, key and host CAs
	"secret": {"credential", "", ""}, "secret.set": {"credential", "", "add"}, "secret.show": {"credential", "", "show"}, "secret.rename": {"credential", "", "rename"},
	"secret.rm": {"credential", "", "remove"}, "secret.check": {"credential", "", "check"}, "secret.cp": {"credential", "", "cp"}, "key": {"credential", "key", ""},
	"host.ca": {"credential", "certificate", ""}, "host.ca.revoke": {"credential", "certificate", "revoke"},

	// komando's own nouns
	"group": {"group", "", ""}, "recipe": {"snippet", "", ""}, "policy": {"policy", "", ""}, "config": {"config", "", ""},
	"guide": {"agent", "", ""}, "guide.guard": {"agent", "", "guard"},
}
