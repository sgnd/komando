package capability

import "slices"

// Replaced is a command of today that exec, query or raw does after the
// cut (a Leaf.Carries entry), with what keeps its protection: the cut
// plan's "Carried by" column, sections 1.4 to 1.6 and 1.8. Pre-cut: it
// goes with the other fates at the cut.
type Replaced struct {
	Today     string
	Rows      []Key    // v2.7 tier rows, by their key, that reach the carrying leaf
	Rules     []string // internal/policy rule IDs
	SQLRules  []string // rule IDs of the SQL classifier (internal/driver SQLRules)
	EveryRule bool     // every policy rule checks the text, as today's command did
	Tests     []string // the tests that pin the rules or the rating, by function name
	Stops     []string // in-command stops, by function name
	NoRule    string   // why no policy rule carries it ("" when one does)
	Lost      string   // what goes on purpose, in the plan's words
}

// Replacements returns today's commands that exec, query or raw does now.
func Replacements() []Replaced { return slices.Clone(replaced) }

// The plan's [exec]: the leaf host ssh exec, its rows (host exec,
// dangerous when the text matches a rule; --stop and --remove, change)
// and the stop refuseEncodedSecret.
var (
	execRows  = []Key{{Type: "host", Verb: "exec"}, {Type: "host", Provider: "ssh", Verb: "exec"}}
	execStops = []string{"refuseEncodedSecret"}
	kubeRaw   = []string{"guardCloudLogin", "guardKubePlugin"}
)

// Why no rule, and what is lost, in the plan's words.
const (
	execNoRule  = "read or change today: host ssh exec's rows and refuseEncodedSecret carry it"
	cronNoRule  = "Audit K1: no rule, change tier"
	valueNoRule = "the leaf rates the text itself (by value): dangerous"

	readLost          = "read it with `host ssh exec`; text output, no shape (no built-in snippet, Audit point 1)"
	o24Lost           = "validate, back up and undo, O-24 (Audit K4); accepted as a loss at v0.18.0: nothing writes a credential reference into a config line and an agent cannot change a [hidden] line; a ready-made change snippet is planned after v0.18.0 (row C374)"
	queryPasswordLost = "a password set through query is on the command line; use a person's terminal"
	keyLost           = "the safe key write of --key: the key went in as the user, so a link in their home could not point the write at a root file; write authorized_keys as the user (`su USER -c ...`)"
	memcachedSetLost  = "memcached: a store command needs a data block and `cache memcached raw` does not send one, so a memcached value cannot be set (Redis SET works through raw); found when D4 removed cache set (row C496)"
	manyClustersLost  = "one row per cluster for a group (@prod): raw runs on one cluster at a time; run it on each (found when D4 removed it, row C496)"
	swarmStackLost    = "Swarm: the stack file went over standard input; raw cannot, so the file must be on the manager and `stack deploy -c FILE` reads it there (found when D4 removed it, row C496)"
	helmLost          = "a Secret read through raw is masked, so the Helm releases are read by the built-in snippets helm-list and helm-release, which decode them (row C631)"
	typedLost         = "the typed-name confirm of a person (the raw path asks only for --allow-dangerous); pin: protected --yes through guardConns, a test per type (row C363) (Audit K4)"
)

// execPlain is an exec ID with no rule; lost is "" or the plan's words.
func execPlain(id, lost string) Replaced {
	return Replaced{Today: id, Rows: execRows, Stops: execStops, NoRule: execNoRule, Lost: lost}
}

// execRule is an exec ID the named policy rules carry.
func execRule(id string, rules, tests []string) Replaced {
	return Replaced{Today: id, Rows: execRows, Rules: rules, Tests: tests, Stops: execStops}
}

// byValue is a query or raw ID the leaf's own by-value row carries.
func byValue(id string, row Key, stops []string, lost string) Replaced {
	return Replaced{Today: id, Rows: []Key{row}, Stops: stops, NoRule: valueNoRule, Lost: lost}
}

func names(s ...string) []string { return s }

var replaced = slices.Concat(execReplaced, queryReplaced, rawReplaced)

// execReplaced: plan section 1.4, and the job commands of section 1.8,
// which host ssh exec carries too.
var execReplaced = []Replaced{
	execPlain("cron.list", readLost),
	{Today: "cron.rm", Rows: execRows, Stops: execStops, NoRule: cronNoRule},
	execPlain("cron.set", ""),

	{Today: "docker.compose", Rows: execRows, Rules: names("docker-rm", "docker-kill", "docker-host"), Tests: names("TestRuleDocker"),
		Stops: names("execComposeReason", "refuseEncodedSecret")},
	execRule("docker.exec", names("container-shell"), names("TestRuleContainerShell")),
	execPlain("docker.images", ""),
	execPlain("docker.inspect", readLost),
	execPlain("docker.logs", ""),
	execRule("docker.prune", names("docker-prune"), names("TestRuleDocker")),
	execPlain("docker.ps", ""),
	execPlain("docker.pull", ""),
	execRule("docker.raw", names("docker-rm", "docker-prune", "docker-kill", "docker-host"), names("TestRuleDocker")),
	execPlain("docker.restart", ""),
	execRule("docker.rm", names("docker-rm"), names("TestRuleDocker")),
	execPlain("docker.start", ""),
	execPlain("docker.stats", ""),
	execPlain("docker.stop", ""),

	execPlain("facts", ""),

	execPlain("fs.cat", ""),
	execPlain("fs.chmod", ""),
	execPlain("fs.list", ""),
	execPlain("fs.mkdir", ""),
	execPlain("fs.mv", ""),
	execPlain("fs.replace", o24Lost),
	execPlain("fs.restore", o24Lost),
	execRule("fs.rm", names("rm-files"), names("TestRuleRmFiles")),
	execPlain("fs.stat", readLost),
	execPlain("fs.write", o24Lost),

	execPlain("logs", ""),

	execPlain("net.check", readLost),
	execPlain("net.dns", readLost),
	execPlain("net.http", readLost),
	execPlain("net.ports", readLost),

	execPlain("pkg.install", ""),
	execPlain("pkg.installed", readLost),
	execRule("pkg.rm", names("pkg-remove-essential"), names("TestRulePackages")),
	execPlain("pkg.security", ""),
	execPlain("pkg.update", ""),
	execPlain("pkg.upgradable", readLost),
	execRule("pkg.upgrade", names("pkg-implicit-remove"), names("TestRulePkgImplicitRemove")),

	{Today: "reboot", Rows: execRows, Rules: names("power", "power-systemctl", "win-power"),
		Tests: names("TestCheck", "TestWindowsRules", "TestRulePower"), Stops: execStops,
		Lost: "reboot one server at a time with a boot-ID check, O-23 (Audit K4); `back_after` is no longer returned: the app measures it by calling the `test` leaf until it answers"},

	execPlain("svc.daemon-reload", ""),
	execRule("svc.disable", names("sshd-stop", "win-remote-access"), names("TestSSHStop", "TestWindowsRules")),
	execPlain("svc.enable", ""),
	execPlain("svc.list", ""),
	execPlain("svc.logs", readLost),
	execPlain("svc.reload", ""),
	execPlain("svc.restart", ""),
	execPlain("svc.start", ""),
	execPlain("svc.status", ""),
	execRule("svc.stop", names("sshd-stop", "win-remote-access"), names("TestSSHStop", "TestWindowsRules")),

	{Today: "user.add", Rows: execRows, Rules: names("account-lock"), Tests: names("TestRuleAccountLock"), Stops: execStops, Lost: keyLost},
	execPlain("user.list", readLost),
	execRule("user.lock", names("account-lock"), names("TestRuleAccountLock")),
	execRule("user.rm", names("userdel", "win-user-delete"), names("TestCheck", "TestWindowsRules", "TestRuleUserdel")),
	execPlain("user.unlock", ""),

	// section 1.8 (removed on purpose): the job commands
	execPlain("job.kill", ""),
	execPlain("job.logs", ""),
	execPlain("job.rm", ""),
	{Today: "job.start", Rows: execRows, EveryRule: true, Tests: names("TestCheck"), Stops: execStops},
	execPlain("job.status", ""),
	execPlain("job.wait", ""),
}

var dbQuery = Key{Type: "database", Verb: "query"}

// queryReplaced: plan section 1.5.
var queryReplaced = []Replaced{
	byValue("db.activity", dbQuery, nil, ""),
	{Today: "db.explain", Rows: []Key{dbQuery}, Tests: names("TestClassifySQL"),
		NoRule: valueNoRule + "; EXPLAIN ANALYZE is rated by the statement it runs"},
	byValue("db.grant", dbQuery, nil, ""),
	byValue("db.info", dbQuery, nil, ""),
	{Today: "db.kill", Rows: []Key{dbQuery}, SQLRules: names("sql-kill"), Tests: names("TestClassifySQL", "TestSessionControlSQL")},
	byValue("db.locks", dbQuery, nil, ""),
	byValue("db.revoke", dbQuery, nil, ""),
	byValue("db.schema", dbQuery, nil, ""),
	byValue("db.sizes", dbQuery, nil, ""),
	{Today: "db.user.add", Rows: []Key{dbQuery}, Tests: names("TestMaskSQLPasswords"), NoRule: valueNoRule, Lost: queryPasswordLost},
	byValue("db.user.list", dbQuery, nil, ""),
	{Today: "db.user.passwd", Rows: []Key{dbQuery}, Tests: names("TestMaskSQLPasswords"), NoRule: valueNoRule, Lost: queryPasswordLost},
	{Today: "db.user.rm", Rows: []Key{dbQuery}, Rules: names("db-drop-user"), Tests: names("TestRuleDBDropUser")},
	byValue("db.user.show", dbQuery, nil, ""),
}

var (
	cacheRaw   = Key{Type: "cache", Verb: "raw"}
	clusterRaw = Key{Type: "cluster", Verb: "raw"}
)

// rawReplaced: plan section 1.6.
var rawReplaced = []Replaced{
	byValue("cache.get", cacheRaw, nil, ""),
	byValue("cache.info", cacheRaw, nil, ""),
	byValue("cache.keys", cacheRaw, nil, ""),
	byValue("cache.rm", cacheRaw, nil, typedLost),
	byValue("cache.set", cacheRaw, nil, memcachedSetLost),

	byValue("cluster.apply", clusterRaw, kubeRaw, swarmStackLost),
	byValue("cluster.deploy", clusterRaw, kubeRaw, ""),
	byValue("cluster.describe", clusterRaw, kubeRaw, ""),
	byValue("cluster.events", clusterRaw, kubeRaw, manyClustersLost),
	byValue("cluster.get", clusterRaw, kubeRaw, ""),
	byValue("cluster.helm.history", clusterRaw, kubeRaw, helmLost),
	byValue("cluster.helm.list", clusterRaw, kubeRaw, helmLost),
	byValue("cluster.helm.status", clusterRaw, kubeRaw, helmLost),
	byValue("cluster.helm.values", clusterRaw, kubeRaw, helmLost),
	byValue("cluster.history", clusterRaw, kubeRaw, ""),
	byValue("cluster.list", clusterRaw, kubeRaw, manyClustersLost),
	byValue("cluster.logs", clusterRaw, kubeRaw, ""),
	byValue("cluster.restart", clusterRaw, kubeRaw, ""),
	byValue("cluster.rm", clusterRaw, kubeRaw, typedLost),
	byValue("cluster.rollback", clusterRaw, kubeRaw, ""),
	{Today: "cluster.scale", Rows: []Key{clusterRaw}, Rules: names("kubectl-scale-zero"), Tests: names("TestRuleKubectlScaleZero"),
		Stops: kubeRaw, Lost: typedLost},
	byValue("cluster.status", clusterRaw, kubeRaw, manyClustersLost),
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
