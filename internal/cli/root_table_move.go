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

// moveLeaves is moveType over the table leaves.
func moveLeaves(typ string, leaves []capability.Leaf) {
	movedTypes = append(movedTypes, typ)
	providerIDs[typ] = true // the type's own group shares its key with the provider groups
	tables := idTables()
	carried := map[string][]map[string]any{} // per new ID, per table, the entries it carries
	var built []capability.Leaf
	var order []int
	stays := map[string]bool{}
	for n, l := range leaves {
		if l.State != capability.Built {
			continue
		}
		if !slices.Contains(movedTypes, l.Type) {
			for _, id := range slices.Concat(l.Today, l.Carries) {
				stays[id] = true
			}
		}
		if l.Type != typ {
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
			if i >= 2 {
				gkey.area = words[2]
			}
			cmdKeys[gid], providerIDs[gid] = gkey, true
			if _, ok := gateNoNetwork[typ]; ok {
				gateNoNetwork[gid] = nil
			}
		}
		for i, tb := range tables {
			for _, old := range slices.Sorted(maps.Keys(carried[id][i])) {
				tb.set(id, joinEntry(tb, id, old, carried[id][i][old]))
			}
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
			if carriedByMoved(cid) {
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
}

// carriedByMoved says whether every built leaf that carries id is of a moved
// type (hideCarried then takes the command out of the tree).
func carriedByMoved(id string) bool {
	for _, r := range capability.Replacements() {
		if r.Today == id {
			return false // exec, query or raw replaces it: it stays until cut step D
		}
	}
	found := false
	for _, l := range capability.All() {
		if l.State == capability.Built && slices.Contains(l.Carries, id) {
			found = true
			if !slices.Contains(movedTypes, l.Type) {
				return false
			}
		}
	}
	return found
}

// joinEntry is the entry id gets in tb when it carries old's entry v as
// well as the one it may have already: the stricter of the two, a check
// over no check. Two different checks mean the tables disagree, and the
// program stops at start (moveType runs in init).
func joinEntry(tb idTable, id, old string, v any) any {
	have, ok := tb.get(id)
	switch {
	case !ok || noCheck(have) || sameEntry(have, v):
		return v
	case noCheck(v):
		return have
	}
	panic("komando: " + id + " carries two different " + tb.name + " entries, one from " + old)
}
