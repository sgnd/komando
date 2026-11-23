package cli

import "github.com/sgnd/komando/internal/capability"

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

// cmdKeys is each command ID's key. The keys live in internal/capability:
// a leaf's own key for the commands it keeps (Leaf.Today), its list of
// today-only keys for the rest.
var cmdKeys = todayKeys()

func todayKeys() map[string]safetyKey {
	keys := map[string]safetyKey{}
	for id, k := range capability.TodayKeys() {
		keys[id] = safetyKey{k.Type, k.Area, k.Verb}
	}
	return keys
}

// keyID is the command ID key names, or "" when no command has it.
func keyID(key safetyKey) string {
	for id, k := range cmdKeys {
		if k == key {
			return id
		}
	}
	return ""
}
