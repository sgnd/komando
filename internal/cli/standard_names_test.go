package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// findCmd finds the command komando runs for args, through aliases.
func findCmd(t *testing.T, root *cobra.Command, args ...string) *cobra.Command {
	t.Helper()
	c, rest, err := root.Find(args)
	if err != nil || c == root || len(rest) > 0 {
		t.Fatalf("%v: no command (%v, rest %v)", args, err, rest)
	}
	return c
}

// A renamed command keeps its ID (S-1.6) under the new name and under the
// old one, which stays a permanent synonym (S-1.7).
func TestStandardRenamedIDs(t *testing.T) {
	root := newRoot()
	for _, c := range []struct {
		now, old []string
		id       string
	}{
		{[]string{"host", "rename"}, []string{"host", "mv"}, "host.mv"},
		{[]string{"conn", "rename"}, []string{"conn", "mv"}, "conn.mv"},
		{[]string{"vpn", "rename"}, []string{"vpn", "mv"}, "vpn.mv"},
		{[]string{"key", "rename"}, []string{"key", "mv"}, "key.mv"},
		{[]string{"secret", "rename"}, []string{"secret", "mv"}, "secret.mv"},
		{[]string{"group", "rename"}, []string{"group", "mv"}, "group.mv"},
		{[]string{"secret", "show"}, []string{"secret", "get"}, "secret.get"},
	} {
		now, old := findCmd(t, root, c.now...), findCmd(t, root, c.old...)
		if now != old {
			t.Errorf("%v and %v run different commands", c.now, c.old)
		}
		if got := cmdID(now); got != c.id {
			t.Errorf("%v: ID %q, want %q", c.now, got, c.id)
		}
		if now.Name() != c.now[len(c.now)-1] || now.Hidden {
			t.Errorf("%v: the new name must be the visible primary (got %q)", c.now, now.Name())
		}
	}
}

// Renaming through the old name works, prints the same command ID and is
// a silent synonym: no meta.deprecated.
func TestRenameOldVerbStillWorks(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	d := mustRun(t, "host", "mv", "web1", "web-01")
	if m := d["_meta"].(map[string]any); m["deprecated"] != nil {
		t.Errorf("host mv is a permanent synonym, not a retired name: %v", m)
	}
	if d := mustRun(t, "host", "rename", "web-01", "web-02"); d["to"] != "web-02" {
		t.Errorf("host rename: %v", d)
	}
	code, outText := runMain(t, "host", "rename", "web-02", "web-03")
	if code != 0 || !strings.Contains(outText, `"command":"host.mv"`) {
		t.Errorf("host rename: exit %d, %s", code, outText)
	}
}
