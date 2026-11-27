package cli

import "slices"

// removedIDs are the commands step D of the v0.18.0 cut took out of the
// tree (exec carries their jobs: capability.Replacements). Their entries
// leave cmdKeys and every table keyed by command ID, and the rows of their
// keys leave riskRows, so no table names a command that is gone
// (TestSafetyKeys, TestSafetyTablesPinned). The list goes with the fate
// tables after the release.
var removedIDs = []string{
	"job", "job.kill", "job.list", "job.logs", "job.rm", "job.start", "job.status", "job.wait",
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
