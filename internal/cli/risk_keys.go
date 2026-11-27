package cli

import (
	"reflect"
	"strings"

	"github.com/sgnd/komando/internal/capability"
)

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
	found := ""
	for id, k := range cmdKeys {
		if k == key && (found == "" || providerOrder[id] < providerOrder[found] ||
			providerOrder[id] == providerOrder[found] && id < found) { // providers share a key: the first of the table speaks for them
			found = id
		}
	}
	return found
}

// idTable is a table keyed by command ID whose entries move with a
// command to its new ID when its type moves (moveType).
type idTable struct {
	name string
	ids  func() []string // the IDs it has an entry for
	get  func(id string) (any, bool)
	set  func(id string, v any)
	drop func(id string)
}

// idTableOf makes m an idTable. spaced is for a table keyed by the words of
// the ID with spaces (personalCmds).
func idTableOf[V any](name string, m map[string]V, spaced bool) idTable {
	key := func(id string) string {
		if spaced {
			return strings.ReplaceAll(id, ".", " ")
		}
		return id
	}
	return idTable{name,
		func() []string {
			var ids []string
			for k := range m {
				ids = append(ids, strings.ReplaceAll(k, " ", "."))
			}
			return ids
		},
		func(id string) (any, bool) { v, ok := m[key(id)]; return v, ok },
		func(id string, v any) { m[key(id)] = v.(V) },
		func(id string) { delete(m, key(id)) }}
}

// idTables are the tables keyed by command ID, which moveType moves, besides
// cmdKeys (a new ID's key is its leaf's). A new table keyed by command ID
// joins here; the tests of moveType and TestSafetyTablesFollowTheLeaf
// read this list, never one of their own.
func idTables() []idTable {
	return []idTable{
		idTableOf("personalCmds", personalCmds, true),
		idTableOf("localReads", localReads, false),
		idTableOf("leavesHome", leavesHome, false),
		idTableOf("gateNetwork", gateNetwork, false),
		idTableOf("gateNoNetwork", gateNoNetwork, false),
		idTableOf("gateLocalFlags", gateLocalFlags, false),
		idTableOf("gateLocalArgs", gateLocalArgs, false),
	}
}

// sameEntry says whether two entries of an idTable are the same: a func
// (a gate check) by the function it is.
func sameEntry(a, b any) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Kind() == reflect.Func && vb.Kind() == reflect.Func {
		return va.Pointer() == vb.Pointer()
	}
	return reflect.DeepEqual(a, b)
}

// noCheck is an entry that is a func with no check in it: a gate entry
// that lets every form of the command run.
func noCheck(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Func && rv.IsNil()
}
