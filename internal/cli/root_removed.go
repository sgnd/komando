package cli

import "slices"

// removedIDs are the commands step D of the v0.18.0 cut took out of the
// tree (exec carries their jobs: capability.Replacements). Their entries
// leave cmdKeys and every table keyed by command ID, and the rows of their
// keys leave riskRows, so no table names a command that is gone
// (TestSafetyKeys, TestSafetyTablesPinned). The list goes with the fate
// tables after the release.
var removedIDs = []string{
	"cron", "cron.list", "cron.rm", "cron.set", "facts",
	"net", "net.check", "net.dns", "net.http", "net.ports", "reboot",
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

// shareEntries gives the command to the entries the command from has in the
// tables keyed by ID: show reads what list reads (group show, snippet show).
func shareEntries(from, to string) {
	for _, tb := range idTables() {
		if v, ok := tb.get(from); ok {
			tb.set(to, v)
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
