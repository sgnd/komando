package cli

import (
	"strings"
	"testing"
)

// `komando db ls` and the like: the data groups have no inventory verbs,
// so the unknown-command error names the shared command that does it.
func TestDataGroupInventoryVerbsPointToSharedCommands(t *testing.T) {
	invHome(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"db", "ls"}, "komando list kind:db"},
		{[]string{"db", "list"}, "komando list kind:db"},
		{[]string{"db", "rm", "shop"}, "komando conn rm NAME"},
		{[]string{"db", "remove", "shop"}, "komando conn rm NAME"},
		{[]string{"cache", "show", "c1"}, "komando conn show NAME"},
		{[]string{"queue", "edit", "q1"}, "komando conn edit NAME"},
		{[]string{"storage", "test", "s1"}, "komando test NAME"},
		{[]string{"cluster", "mv", "a", "b"}, "komando conn rename OLD NEW"},
		{[]string{"registry", "test", "r1"}, "komando test NAME"},
	} {
		e := wantCode(t, "USAGE", c.args...)
		if !strings.Contains(e.Hint, c.want) || !strings.Contains(e.Message, "unknown command") {
			t.Errorf("%v: %+v", c.args, e)
		}
	}
	// a verb the group has is not touched, and other groups keep the plain hint
	if e := wantCode(t, "USAGE", "host", "frobnicate"); strings.Contains(e.Hint, "komando conn") {
		t.Errorf("host: %+v", e)
	}
}
