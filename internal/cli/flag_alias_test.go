package cli

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// gateReadFlags are the flags the ssh gate reads to tell a read from a
// change (gateReadForm, gateSavesHere, gateSetDefault).
var gateReadFlags = []string{"read-only", "write", "analyze", "refresh", "to", "set-default"}

// Every hidden flag spelling shares the value of the flag it stands for,
// and the ssh gate gives the same answer for every spelling of each flag
// it reads (S-5.18).
func TestStandardAliasSpelling(t *testing.T) {
	for _, c := range allCommands(newRoot(tcl)) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			a := f.Annotations[flagAliasOf]
			if a == nil {
				return
			}
			now := c.Flags().Lookup(a[0])
			switch {
			case !f.Hidden:
				t.Errorf("%s --%s: a flag spelling is hidden", c.CommandPath(), f.Name)
			case now == nil:
				t.Errorf("%s --%s: stands for --%s, which is no flag", c.CommandPath(), f.Name, a[0])
			case now.Value != f.Value && !wrapsValue(f.Value, now.Value):
				t.Errorf("%s --%s: does not share the value of --%s", c.CommandPath(), f.Name, a[0])
			}
		})
	}
	n := 0
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		_, read := gateReadForm[id]
		_, saves := gateSavesHere[id]
		_, change := gateOnServers[id]
		if !read && !saves && !change {
			continue
		}
		for _, flag := range gateReadFlags {
			if c.Flags().Lookup(flag) == nil || len(flagSpellings(c, flag)) == 1 {
				continue
			}
			want := spellingAnswer(t, id, "--"+flag, "")
			for _, sp := range flagSpellings(c, flag)[1:] {
				n++
				if got := spellingAnswer(t, id, "--"+sp, ""); got != want {
					t.Errorf("%s --%s: the gate says %q, for --%s %q", id, sp, got, flag, want)
				}
			}
		}
	}
	t.Logf("%d hidden spellings of gate-read flags checked", n)
}

// wrapsValue reports whether v sets base itself after a check of its own
// (cluster -n, which refuses a number first): the same variable.
func wrapsValue(v, base pflag.Value) bool {
	w, ok := v.(interface{ wraps() pflag.Value })
	return ok && w.wraps() == base
}

// spellingAnswer is the code a read-only gate key gets for command id given
// flag (and value), from a fresh tree; extra adds a spelling first.
func spellingAnswer(t *testing.T, id, flag, alias string) string {
	t.Helper()
	saved := tcl.flags
	tcl.flags = globalFlags{}
	defer func() { tcl.flags = saved }()
	var c *cobra.Command
	for _, x := range allCommands(newRoot(tcl)) {
		if cmdID(x) == id {
			c = x
		}
	}
	if alias != "" {
		flagAlias(c, alias, flag[2:])
		flag = "--" + alias
	}
	args := []string{flag}
	if f := c.Flags().Lookup(flag[2:]); f != nil && f.NoOptDefVal == "" {
		args = append(args, "x")
	}
	if err := c.ParseFlags(args); err != nil {
		t.Fatalf("%s %v: %v", id, args, err)
	}
	if _, e := gateRule(c, id, true); e != nil {
		return e.Code
	}
	return ""
}

// A new hidden spelling of a gate-read flag is refused by a read-only key
// as the flag itself is: pkg upgradable --refresh under another name.
func TestAliasSpellingReachesGate(t *testing.T) {
	for _, c := range []struct{ id, flag string }{
		{"pkg.upgradable", "--refresh"}, {"db.query", "--write"}, {"cache.run", "--write"},
		{"cluster.run", "--write"}, {"db.explain", "--analyze"}, {"pkg.security", "--refresh"},
	} {
		if got := spellingAnswer(t, c.id, c.flag, "old-spelling"); got != "SSH_GATE_READ_ONLY" {
			t.Errorf("%s under a hidden spelling of %s: %q, want SSH_GATE_READ_ONLY", c.id, c.flag, got)
		}
		if got := spellingAnswer(t, c.id, c.flag, ""); got != "SSH_GATE_READ_ONLY" {
			t.Errorf("%s %s: %q", c.id, c.flag, got)
		}
	}
	// --read-only under another spelling still says the command only reads
	if got := spellingAnswer(t, "exec", "--read-only", "only-reads"); got != "" {
		t.Errorf("exec --only-reads: %q", got)
	}
}

// A hidden spelling shares the flag's value, and flagChanged and
// flagSpellings see it.
func TestFlagAliasSharesValue(t *testing.T) {
	var v bool
	c := &cobra.Command{Use: "y"}
	c.Flags().BoolVar(&v, "refresh", false, "")
	flagAlias(c, "renew", "refresh")
	if err := c.ParseFlags([]string{"--renew"}); err != nil || !v || !flagChanged(c, "refresh") {
		t.Fatalf("parse: %v %v", err, v)
	}
	if got := flagSpellings(c, "refresh"); !slices.Equal(got, []string{"refresh", "renew"}) {
		t.Errorf("spellings %v", got)
	}
}
