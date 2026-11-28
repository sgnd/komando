package cli

import "slices"

// removedIDs are the commands step D of the v0.18.0 cut took out of the
// tree (exec carries their jobs: capability.Replacements). Their entries
// leave cmdKeys and every table keyed by command ID, and the rows of their
// keys leave riskRows, so no table names a command that is gone
// (TestSafetyKeys, TestSafetyTablesPinned). The list goes with the fate
// tables after the release.
var removedIDs = []string{
	"cache.get", "cache.info", "cache.keys", "cache.rm", "cache.set",
	"cert", "cert.check",
	"cluster.apply", "cluster.deploy", "cluster.describe", "cluster.events", "cluster.get",
	"cluster.helm", "cluster.helm.history", "cluster.helm.list", "cluster.helm.status", "cluster.helm.values",
	"cluster.history", "cluster.list", "cluster.logs", "cluster.restart", "cluster.rm", "cluster.rollback",
	"cluster.scale", "cluster.status",
	"conn.kinds",
	"cron", "cron.list", "cron.rm", "cron.set", "environment", "exit-codes", "facts", "help",
	"host.ca", "host.ca.revoke", "host.ssh-command",
	"job", "job.kill", "job.list", "job.logs", "job.rm", "job.start", "job.status", "job.wait",
	"net", "net.check", "net.dns", "net.http", "net.ports", "output", "reboot", "rename", "safety",
	"secret", "secret.check", "secret.cp",
	"svc", "svc.daemon-reload", "svc.disable", "svc.enable", "svc.list", "svc.logs", "svc.reload",
	"svc.restart", "svc.start", "svc.status", "svc.stop",
	"user", "user.add", "user.list", "user.lock", "user.rm", "user.unlock",
	"recipe", // the noun is snippet now (cut step C8)
}

func init() { dropRemoved(removedIDs) }

// keepNounEntries keeps the entries the ID of a noun has in the tables keyed
// by ID through moveType: a noun that shares its ID with the command that
// moved under it (audit) is still a command, and moveType takes the
// entries of the old ID to the leaf. Call the returned func after moveType.
func keepNounEntries(id string) func() {
	tables := idTables()
	got := make([]any, len(tables))
	has := make([]bool, len(tables))
	for i, tb := range tables {
		got[i], has[i] = tb.get(id)
	}
	return func() {
		for i, tb := range tables {
			if has[i] {
				tb.set(id, got[i])
			}
		}
	}
}

// dropRemoved takes ids out of cmdKeys and the tables keyed by ID, and the
// rows of the keys no command has any more out of riskRows.
func dropRemoved(ids []string) {
	keys := map[safetyKey]bool{}
	for _, id := range ids {
		if k, ok := cmdKeys[id]; ok {
			keys[k] = true
		}
		delete(cmdKeys, id)
		for _, tb := range idTables() {
			tb.drop(id)
		}
	}
	for _, k := range cmdKeys {
		delete(keys, k) // a key a live command still has keeps its rows
	}
	riskRows = slices.DeleteFunc(riskRows, func(r riskRow) bool { return keys[r.key] })
}
