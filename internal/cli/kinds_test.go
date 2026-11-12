package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestEveryCommandHasKind: a new command cannot ship without saying whether
// it reads or changes things, and the table holds no command that is gone.
func TestEveryCommandHasKind(t *testing.T) {
	seen := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		if c.HasParent() && c.Runnable() {
			key := idKey(c)
			seen[key] = true
			k, ok := kindOf(c)
			switch {
			case !ok:
				t.Errorf("%q has no kind: add it to commandKinds in kinds.go (reads, changes or dependsOn)", key)
			case k.Kind == kindDepends && k.Note == "":
				t.Errorf("%q: dependsOn needs a note saying on what", key)
			case k.Kind != kindDepends && k.Note != "":
				t.Errorf("%q: only dependsOn has a note", key)
			}
			// a command that only reads has nothing to allow or confirm
			if ok && k.Kind == kindRead {
				for _, f := range []string{"allow-dangerous", "write"} {
					if c.LocalFlags().Lookup(f) != nil {
						t.Errorf("%q is marked reads but has --%s: mark it changes or dependsOn", key, f)
					}
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot())
	for key := range commandKinds {
		if !seen[key] {
			t.Errorf("commandKinds has %q, but there is no such command: remove it", key)
		}
	}
}
