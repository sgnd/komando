package cli

import (
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
