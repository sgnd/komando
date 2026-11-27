package cli

import (
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/capability"
)

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
		idTableOf("revealNever", revealNever, false),
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

// moveType makes a type's built leaves the commands of their IDs in every
// table keyed by ID, in the same step that registers their handlers: the
// new IDs get the safety key of the leaf, and every entry that the IDs the
// leaf names (Today and Carries) have in idTables, read before any table
// changes, so every provider of a type gets the same entries. Only then do
// the old IDs lose theirs, so no table names a command that is gone; an ID
// that a type not moved yet still names keeps them.
func moveType(typ string) { moveLeaves(typ, capability.All()) }

// moveTop is moveType for a top-level leaf (copy): what it carries leaves the tables.
func moveTop(verb string) {
	movedTop = append(movedTop, verb)
	moveWhere("", capability.All(), func(l capability.Leaf) bool { return l.Type == "" && l.Verb == verb })
}

// leafMoved says whether l's type, or l itself when it is a top-level leaf, has moved.
func leafMoved(l capability.Leaf) bool {
	if l.Type == "" {
		return slices.Contains(movedTop, l.Verb)
	}
	return slices.Contains(movedTypes, l.Type)
}

// moveLeaves is moveType over the table leaves.
func moveLeaves(typ string, leaves []capability.Leaf) {
	movedTypes = append(movedTypes, typ)
	providerIDs[typ] = true // the type's own group shares its key with the provider groups
	if old := familyOfType(typ); old != typ {
		// the type's group had another word today (db): the new group gets
		// its key and its gate entry; the old group keeps them while it
		// still holds commands
		cmdKeys[typ] = safetyKey{typ: typ}
		providerIDs[old] = true // the old group runs nothing of its own either
		if v, ok := gateNoNetwork[old]; ok {
			gateNoNetwork[typ] = v
		}
	}
	moveWhere(typ, leaves, func(l capability.Leaf) bool { return l.Type == typ })
}

// moveWhere moves the built leaves pick selects.
func moveWhere(typ string, leaves []capability.Leaf, pick func(capability.Leaf) bool) {
	tables := idTables()
	carried := map[string][]map[string]any{} // per new ID, per table, the entries it carries
	var built []capability.Leaf
	var order []int
	stays := map[string]bool{}
	carriedAway := carriedByMovedIn(leaves)
	for n, l := range leaves {
		if l.State != capability.Built {
			continue
		}
		if !leafMoved(l) {
			for _, id := range slices.Concat(l.Today, l.Carries) {
				stays[id] = true
			}
		}
		if !pick(l) {
			continue
		}
		id := strings.Join(l.Key.Path(), ".")
		stays[id] = true
		built, order = append(built, l), append(order, n)
		got := make([]map[string]any, len(tables))
		for i, tb := range tables {
			got[i] = map[string]any{}
			for _, old := range slices.Concat(l.Today, l.Carries) {
				if v, ok := tb.get(old); ok {
					got[i][old] = v
				}
			}
		}
		carried[id] = got
	}
	var gone []string
	for k, l := range built {
		words := l.Key.Path()
		id := strings.Join(words, ".")
		providerOrder[id] = order[k]
		cmdKeys[id] = safetyKey{l.Type, l.Area, l.Verb}
		providerIDs[id] = true
		for i := 1; i < len(words)-1; i++ { // the provider and area groups
			gid, gkey := strings.Join(words[:i+1], "."), safetyKey{typ: l.Type}
			if i >= 2 || l.Provider == "" { // komando's own noun has its area first
				gkey.area = words[i]
			}
			cmdKeys[gid], providerIDs[gid] = gkey, true
			if _, ok := gateNoNetwork[typ]; ok { // set above when today's word differs
				gateNoNetwork[gid] = nil
			}
		}
		for i, tb := range tables {
			// the leaf's own commands of today first: their entry is the one a
			// reason or a list keeps when the carried commands have others
			var own, rest []string
			for _, old := range slices.Sorted(maps.Keys(carried[id][i])) {
				if slices.Contains(l.Today, old) {
					own = append(own, old)
				} else {
					rest = append(rest, old)
				}
			}
			for _, old := range append(own, rest...) {
				tb.set(id, joinEntry(tb, id, old, carried[id][i][old]))
			}
		}
		if _, needs := gateNetwork[id]; needs {
			// a leaf that carries reads and a program of your choosing (host ssh
			// exec) has both entries: the reason it needs a network is the one
			delete(gateNoNetwork, id)
		}
		if l.LocalRead {
			localReads[id] = true
		}
		if l.LeavesHome {
			leavesHome[id] = true
		}
		for _, old := range l.Today {
			if !stays[old] {
				gone = append(gone, old)
			}
		}
		for _, cid := range l.Carries { // conn.list stays a command until every type has moved
			if carriedAway(cid) {
				gone = append(gone, cid)
			}
		}
	}
	for _, old := range gone {
		delete(cmdKeys, old)
		for _, tb := range tables {
			tb.drop(old)
		}
	}
	keyGroups(typ, gone, tables)
}

// connVerbsUntilStepD are today's conn commands, which every moved conn type
// carries: they stay in the tree until cut step D moves their callers (hints,
// tests, e2e) to the per-type paths (row C488).
var connVerbsUntilStepD = []string{"conn.add", "conn.edit", "conn.list", "conn.rename", "conn.rm", "conn.show", "conn.test"}

// carriedByMoved says whether every built leaf that carries id is of a moved
// type (hideCarried then takes the command out of the tree).
func carriedByMoved(id string) bool { return carriedByMovedIn(capability.All())(id) }

// carriedByMovedIn is carriedByMoved over leaves, read once: moveLeaves asks
// for every carried ID of a type at start, so a scan for each ID would cost
// every command a run.
func carriedByMovedIn(leaves []capability.Leaf) func(id string) bool {
	carried, waits := map[string]bool{}, map[string]bool{} // carried by a built leaf; by one of a type not moved
	for _, l := range leaves {
		if l.State != capability.Built {
			continue
		}
		moved := leafMoved(l)
		for _, id := range l.Carries {
			carried[id] = true
			waits[id] = waits[id] || !moved
		}
	}
	for _, r := range capability.Replacements() {
		waits[r.Today] = true // exec, query or raw replaces it: it stays until cut step D
	}
	for _, id := range connVerbsUntilStepD {
		waits[id] = true
	}
	return func(id string) bool { return carried[id] && !waits[id] }
}

// joinEntry is the entry id gets in tb when it carries old's entry v as
// well as the one it may have already: the stricter of the two, a check
// over no check. Two reasons (gateNetwork) say the same thing, so the first
// one stays; two lists of flags (gateLocalFlags) join. Two different checks
// mean the tables disagree, and the program stops at start (moveType runs
// in init).
func joinEntry(tb idTable, id, old string, v any) any {
	have, ok := tb.get(id)
	switch {
	case !ok || noCheck(have) || sameEntry(have, v):
		return v
	case noCheck(v):
		return have
	case isString(have) && isString(v):
		return have
	case isStrings(have) && isStrings(v):
		return slices.Compact(slices.Sorted(slices.Values(slices.Concat(have.([]string), v.([]string)))))
	}
	panic("komando: " + id + " carries two different " + tb.name + " entries, one from " + old)
}

func isString(v any) bool { _, ok := v.(string); return ok }

func isStrings(v any) bool { _, ok := v.([]string); return ok }
