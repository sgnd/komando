package cli

import (
	"slices"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/capability"
)

// Chief rule R1 (row C604): every audit record names the leaf that ran
// (command) and its safety key (safety_key: type, area, verb); a record the call
// names itself, an event, adds its name (event) from auditEvents. Records
// already written are never rewritten: `audit --command` finds a v0.17
// record through the key of its ID (auditKeyOf).

// auditEvents is the closed list of event names (TestAuditNamesAreIDsOrListedEvents).
var auditEvents = []string{
	"host.key-pinned",        // a server's key trusted on first use
	"secret.set",             // a password typed with --ask-password, stored
	"login.host",             // a server's login kept open (by test); the name stays so old records and queries still match
	"test.end",               // test --end closed kept logins
	"export.sealed",          // a sealed export file written
	"doctor.accept-old-copy", // a person took an older copy of the store
	"doctor.reseal-meta",     // a person sealed the store's settings row again
	"doctor.end-old-jobs",    // a person marked v0.17 jobs ended; the move writes it
	// the file events of copy
	"upload", "download", "sync", "delete",
}

// auditKeyOf is the safety key of a command ID: one in the tree now, one
// of v0.17 (capability.TodayKeys) or a table leaf's ID before its type
// moves. A spaced ID ("vpn socks add") is read as the dotted one.
func auditKeyOf(id string) (safetyKey, bool) {
	id = strings.Join(strings.Fields(id), ".")
	if k, ok := cmdKeys[id]; ok {
		return k, true
	}
	k, ok := auditKeys()[id]
	return k, ok
}

var auditKeys = sync.OnceValue(func() map[string]safetyKey {
	keys := map[string]safetyKey{}
	for id, k := range capability.TodayKeys() {
		keys[id] = safetyKey{k.Type, k.Area, k.Verb}
	}
	for _, l := range capability.All() {
		keys[strings.Join(l.Key.Path(), ".")] = safetyKey{l.Type, l.Area, l.Verb}
	}
	return keys
})

// keyRecord is how a record writes a safety key.
func keyRecord(k safetyKey) map[string]any {
	return map[string]any{"type": k.typ, "area": k.area, "verb": k.verb}
}

// recordKey is the safety key of a record: its safety_key field, else (a
// v0.17 record) the key of its command ID.
func recordKey(e map[string]any) (safetyKey, bool) {
	if m, ok := e["safety_key"].(map[string]any); ok {
		t, _ := m["type"].(string)
		a, _ := m["area"].(string)
		v, _ := m["verb"].(string)
		return safetyKey{t, a, v}, true
	}
	c, _ := e["command"].(string)
	return auditKeyOf(c)
}

// readOldEvent gives a record written before rule R1 its event: the
// event's name sat in command then, with no event field (C625). The
// record on disk is never rewritten.
func readOldEvent(e map[string]any) {
	if _, has := e["event"]; has {
		return
	}
	if c, _ := e["command"].(string); slices.Contains(auditEvents, c) {
		e["event"] = c
	}
}

// runningLeaf is the ID of the leaf the call runs: the table leaf whose
// body runs (runBody), else the parsed command.
func runningLeaf(cl *call) string {
	if cl.out.As != "" {
		return cl.out.As
	}
	if id := cl.gate().cmdID; id != "" {
		return id
	}
	return "komando"
}
