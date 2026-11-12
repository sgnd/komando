package cli

import (
	"strings"
	"testing"

)

// Every db command names its conn CONN in Use, so completion and the
// prompter's picker find it, and no Use line carries flags (they show in
// [flags] and in the help).
func TestDBUseLines(t *testing.T) {
	root := newRoot()
	db, _, err := root.Find([]string{"db"})
	if err != nil {
		t.Fatal(err)
	}
	stack := db.Commands()
	for len(stack) > 0 {
		c := stack[0]
		stack = append(stack[1:], c.Commands()...)
		if c.HasSubCommands() || c.CommandPath() == "komando db add" {
			continue
		}
		f := strings.Fields(c.Use)
		if len(f) < 2 || f[1] != "CONN" {
			t.Errorf("%s: Use %q: the first argument must be CONN", c.CommandPath(), c.Use)
		}
		if strings.Contains(c.Use, "--") || strings.Contains(c.Use, "(") {
			t.Errorf("%s: Use %q carries flags", c.CommandPath(), c.Use)
		}
	}
}
