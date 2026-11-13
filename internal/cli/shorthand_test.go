package cli

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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

// TestStandardShorthands walks the tree and checks every short letter
// against the reserved table (docs/design/command-standard.md, S-5.14 and
// S-5.15): one meaning per letter within its scope, and none at all for
// the flags that must be typed in full.
func TestStandardShorthands(t *testing.T) {
	in := func(path string, list ...string) bool {
		return slices.Contains(list, strings.TrimPrefix(path, "komando "))
	}
	cluster := func(path string) bool { return strings.HasPrefix(path, "komando cluster ") }
	editOrAdd := func(path string) bool {
		n := path[strings.LastIndex(path, " ")+1:]
		return n == "add" || n == "edit" || n == "import"
	}
	logStreamers := []string{"logs", "svc logs", "docker logs", "cluster logs"}
	// letter -> long flag -> where it may be (nil: everywhere)
	table := map[string]map[string]func(path string) bool{
		"o": {"output": nil}, "P": {"parallel": nil}, "y": {"yes": nil}, "h": {"help": nil},
		"v": {"version": func(p string) bool { return p == "komando" }},
		"a": {"all": func(p string) bool {
			return in(p, "docker ps", "docker prune", "fs list", "user list", "db activity", "cache info", "cluster helm values", "guide")
		}},
		"A": {"all-namespaces": cluster},
		"c": {"container": nil, "cmd": func(p string) bool { return in(p, "exec", "job start") }},
		"C": {"dir": nil, "comment": func(p string) bool { return in(p, "key gen") }},
		"e": {"env": nil},
		"f": {"follow": func(p string) bool { return in(p, logStreamers...) }, "file": func(p string) bool { return !in(p, logStreamers...) }},
		"g": {"group": editOrAdd},
		"l": {"selector": cluster},
		"n": {"namespace": cluster, "limit": func(p string) bool { return !cluster(p) && !in(p, "storage rm") }},
		"p": {"parents": func(p string) bool { return in(p, "cp", "upload", "fs write", "fs replace", "fs mkdir") },
			"priority": func(p string) bool { return in(p, "logs", "svc logs", "docker logs") }},
		"r": {"recursive": nil}, "s": {"sudo": nil},
		"t": {"tag": editOrAdd},
		"u": {"unit": func(p string) bool { return in(p, "logs", "svc logs", "docker logs") }}, // the logs family
		"b": {"bits": func(p string) bool { return in(p, "key gen") }},
		"D": {"dynamic": func(p string) bool { return in(p, "tunnel start") }},
		"L": {"local": func(p string) bool { return in(p, "tunnel start") }},
		"R": {"remote": func(p string) bool { return in(p, "tunnel start") }},
	}
	never := []string{"allow-dangerous", "reveal", "write", "dry-run", "port", "user", "label"}
	root := newRoot()
	check := func(path string, c *cobra.Command, f *pflag.Flag) {
		if f.Shorthand == "" {
			return
		}
		if slices.Contains(never, f.Name) {
			t.Errorf("%s --%s has -%s; it must be typed in full (S-5.15)", path, f.Name, f.Shorthand)
		}
		if f.Name == "all" && c != nil && !in(path, "docker prune") { // docker prune -a: docker's own
			if k, ok := kindOf(c); ok && k.Kind == "change" {
				t.Errorf("%s --all has -a on a change command (S-5.15)", path)
			}
		}
		longs, ok := table[f.Shorthand]
		if !ok {
			t.Errorf("%s --%s: -%s is not in the reserved table; add a row with the reference CLI first", path, f.Name, f.Shorthand)
			return
		}
		where, ok := longs[f.Name]
		if !ok {
			t.Errorf("%s --%s: -%s is reserved for another flag (%v)", path, f.Name, f.Shorthand, slices.Sorted(maps.Keys(longs)))
			return
		}
		if where != nil && !where(path) {
			t.Errorf("%s --%s: -%s is outside its scope here", path, f.Name, f.Shorthand)
		}
	}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) { check("komando", nil, f) })
	root.InitDefaultHelpFlag()
	root.InitDefaultVersionFlag()
	for _, c := range allCommands(root) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) { check(c.CommandPath(), c, f) })
	}
	// the parser's own -n in cluster is the namespace with the number check
	c, _, _ := root.Find([]string{"cluster", "ls"})
	if f := c.Flags().ShorthandLookup("n"); f == nil || f.Value.Type() != "string" {
		t.Errorf("cluster ls: the parser's -n is %+v", f)
	}
}
