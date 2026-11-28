package cli

import "slices"

// removedIDs are the commands step D of the v0.18.0 cut took out of the
// tree (exec carries their jobs: capability.Replacements). Their entries
// leave cmdKeys and every table keyed by command ID, and the rows of their
// keys leave riskRows, so no table names a command that is gone
// (TestSafetyKeys, TestSafetyTablesPinned). The list goes with the fate
// tables after the release.
var removedIDs = []string{
	"cert", "cert.check", "cron", "cron.list", "cron.rm", "cron.set", "environment", "exit-codes", "facts", "help",
	"net", "net.check", "net.dns", "net.http", "net.ports", "output", "reboot", "safety",
	"svc", "svc.daemon-reload", "svc.disable", "svc.enable", "svc.list", "svc.logs", "svc.reload",
	"svc.restart", "svc.start", "svc.status", "svc.stop",
	"user", "user.add", "user.list", "user.lock", "user.rm", "user.unlock",
}

func init() { dropRemoved(removedIDs) }

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
