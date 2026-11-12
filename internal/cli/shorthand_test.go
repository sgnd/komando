package cli

import (
	"testing"
)

// C-S05: fs mkdir always makes the parents, so -p from habit is a hidden
// no-op, not an unknown flag.
func TestFsMkdirParentsNoOp(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	defer func() { g.dryRun = false }()
	plan := func(args ...string) string {
		d := mustRun(t, append([]string{"fs", "mkdir", "web1"}, args...)...)
		delete(d, "_meta")
		return jsonStr(d)
	}
	a := plan("/srv/a/b", "--dry-run")
	for _, p := range []string{"-p", "--parents"} {
		if b := plan(p, "/srv/a/b", "--dry-run"); b != a {
			t.Errorf("%s changes the plan:\n%s\n%s", p, a, b)
		}
	}
	c, _, _ := newRoot().Find([]string{"fs", "mkdir"})
	if f := c.Flags().Lookup("parents"); f == nil || !f.Hidden || f.Shorthand != "p" {
		t.Errorf("--parents: %+v", f)
	}
}
