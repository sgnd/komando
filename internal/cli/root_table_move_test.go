package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
)

// TestConnVerbsUntilStepDHaveTheirLeaves: a conn command kept until cut step
// D is in the tree, and every built leaf that carries it is in the tree on
// its own path, so dropping the list at step D loses no command (row C488).
func TestConnVerbsUntilStepDHaveTheirLeaves(t *testing.T) {
	inTree := map[string]bool{}
	walk(newRoot(tcl), func(c *cobra.Command) { inTree[cmdID(c)] = true })
	for _, id := range connVerbsUntilStepD {
		if !inTree[id] {
			t.Errorf("%s waits for step D but is not in the tree", id)
		}
		carriers := 0
		for _, l := range capability.All() {
			if l.State != capability.Built || !slices.Contains(l.Carries, id) {
				continue
			}
			carriers++
			if path := strings.Join(l.Key.Path(), "."); !inTree[path] {
				t.Errorf("%s is carried by %s, which is not in the tree", id, path)
			}
		}
		if carriers == 0 {
			t.Errorf("no built leaf carries %s: take it off connVerbsUntilStepD", id)
		}
	}
}

// A move reads every leaf but pays only for the ones it moves: the start
// runs one move per type (scripts/start-time.sh).
func TestMoveCostDoesNotGrowWithLeavesItLeaves(t *testing.T) {
	none := func(capability.Leaf) bool { return false }
	leaves := capability.All()
	twice := slices.Concat(leaves, leaves)
	one := testing.AllocsPerRun(5, func() { moveWhere("", leaves, none) })
	two := testing.AllocsPerRun(5, func() { moveWhere("", twice, none) })
	if two > one {
		t.Errorf("a move that moves nothing: %.0f allocations over the table, %.0f over it twice, want no more", one, two)
	}
}

// A moved leaf that carries no table's entry costs no map per table.
func TestMovedLeafWithNoEntriesCostsLittle(t *testing.T) {
	t.Cleanup(func() {
		maps.DeleteFunc(cmdKeys, func(id string, _ safetyKey) bool { return strings.HasPrefix(id, "zzmove") })
		maps.DeleteFunc(providerIDs, func(id string, _ bool) bool { return strings.HasPrefix(id, "zzmove") })
		maps.DeleteFunc(providerOrder, func(id string, _ int) bool { return strings.HasPrefix(id, "zzmove") })
	})
	fake := func(n int) []capability.Leaf {
		var ls []capability.Leaf
		for i := range n {
			ls = append(ls, capability.Leaf{Key: capability.Key{Type: "zzmove", Area: "a", Verb: fmt.Sprintf("v%03d", i)}, State: capability.Built})
		}
		return ls
	}
	pick := func(l capability.Leaf) bool { return l.Type == "zzmove" }
	few, many := fake(1), fake(41)
	one := testing.AllocsPerRun(5, func() { moveWhere("zzmove", few, pick) })
	more := testing.AllocsPerRun(5, func() { moveWhere("zzmove", many, pick) })
	if per, tables := (more-one)/40, len(idTables()); per >= float64(tables) {
		t.Errorf("a moved leaf with no entries: %.1f allocations each, want under %d (one map per table)", per, tables)
	}
}
