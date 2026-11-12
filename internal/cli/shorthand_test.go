package cli

import (
	"strings"
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

// C-S04: an unknown short letter gets a did-you-mean: the habits of
// other tools first, then the long flags with that letter; never an
// approval flag.
func TestShorthandDidYouMean(t *testing.T) {
	invHome(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"fs", "ls", "web1", "/", "-n", "5"}, ""}, // fs ls has no --limit yet
		{[]string{"db", "sizes", "x1", "-n", "5"}, ""},     // has -n
		{[]string{"docker", "exec", "web1", "api", "-it", "--", "sh"}, "`komando shell TARGET`"},
		{[]string{"cluster", "exec", "k", "api", "-it", "--", "sh"}, "`komando cluster shell TARGET POD`"},
		{[]string{"exec", "web1", "-L", "8080:localhost:80", "--", "true"}, "`komando tunnel start TARGET -L SPEC`"},
		{[]string{"svc", "restart", "web1", "nginx", "-w", "10s"}, "did you mean --wait?"},
		{[]string{"cache", "get", "c1", "k", "-x"}, ""},
		{[]string{"fs", "replace", "web1", "/etc/x", "-b"}, "did you mean --backup?"},
		{[]string{"queue", "ls", "q1", "-j"}, ""},
	} {
		e := mainErr(t, c.args...)
		if e.Code != "USAGE" {
			if c.want != "" {
				t.Errorf("%v: %+v", c.args, e)
			}
			continue
		}
		if c.want != "" && !strings.Contains(e.Message, c.want) {
			t.Errorf("%v: %q, want %q in it", c.args, e.Message, c.want)
		}
		if strings.Contains(e.Message, "--yes") || strings.Contains(e.Message, "--allow-dangerous") || strings.Contains(e.Message, "--reveal") {
			t.Errorf("%v suggests an approval flag: %q", c.args, e.Message)
		}
	}
	c, _, _ := newRoot().Find([]string{"fs", "ls"})
	_ = c.ParseFlags(nil)
	if s := shorthandSuggest(c, "y", "-y"); s != "" {
		t.Errorf("-y on fs ls suggests %q", s)
	}
	if s := shorthandSuggest(c, "a", "-a"); s != "did you mean --all?" {
		t.Errorf("-a: %q", s)
	}
}
