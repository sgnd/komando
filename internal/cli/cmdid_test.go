package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// allCommands is every command under root, hidden ones too.
func allCommands(root *cobra.Command) []*cobra.Command {
	var all []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		all = append(all, c)
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return all
}

// treeIDs is the set of command IDs in the tree.
func treeIDs(t *testing.T) map[string]*cobra.Command {
	t.Helper()
	ids := map[string]*cobra.Command{}
	for _, c := range allCommands(newRoot()) {
		if strings.ContainsAny(c.Name(), ". ") {
			t.Errorf("%q: a command name has no dot or space (IDs are dotted paths)", c.CommandPath())
		}
		if c.Annotations[cmdIDNote] == "" {
			t.Errorf("%q has no ID annotation", c.CommandPath())
		}
		ids[cmdID(c)] = c
	}
	return ids
}

// A command ID never changes and never goes away (S-1.6): every ID in
// testdata/command_ids.txt is still in the tree, and a new command is added
// there. KOMANDO_GOLDEN_UPDATE=1 writes the file again (only on purpose: an
// ID that disappears means a rename that forgot withID).
func TestCommandIDsStable(t *testing.T) {
	ids := treeIDs(t)
	var got []string
	for id, c := range ids {
		if strings.HasPrefix(c.Name(), "__") {
			continue // cobra's completion plumbing, added as it runs
		}
		got = append(got, id)
	}
	slices.Sort(got)
	file := filepath.Join("testdata", "command_ids.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(file, []byte(strings.Join(got, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(b))
	for _, id := range want {
		if _, ok := ids[id]; !ok {
			t.Errorf("command ID %q is gone: a renamed command keeps its ID (withID(c, %q)); a removed one stays as a hidden alias", id, id)
		}
	}
	for _, id := range got {
		if !slices.Contains(want, id) {
			t.Errorf("new command ID %q: add it to testdata/command_ids.txt", id)
		}
	}
}

// Every key in every table keyed by command names a command ID, so a
// rename that forgot withID fails here instead of slipping past a check.
func TestTablesKeyedByID(t *testing.T) {
	ids := treeIDs(t)
	check := func(table, key string) {
		id := strings.ReplaceAll(key, " ", ".")
		if _, ok := ids[id]; !ok {
			t.Errorf("%s has %q, which is no command ID", table, key)
		}
	}
	tables := map[string][]string{}
	add := func(name string, keys []string) { tables[name] = keys }
	add("commandKinds", keysOf(commandKinds))
	add("personalCmds", keysOf(personalCmds))
	add("localReads", keysOf(localReads))
	add("leavesHome", keysOf(leavesHome))
	add("gateReadForm", keysOf(gateReadForm))
	add("gateNotForReadKey", keysOf(gateNotForReadKey))
	add("gateOnServers", keysOf(gateOnServers))
	add("gateSavesHere", keysOf(gateSavesHere))
	add("gateNeedsPerson", keysOf(gateNeedsPerson))
	add("gateTargetArgs", keysOf(gateTargetArgs))
	add("mask line", []string{"secret.get"})
	for name, keys := range tables {
		for _, k := range keys {
			check(name, k)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// A command typed by any of its names has the same ID: the masking, the
// ssh-gate tables and the envelopes see one command.
func TestAliasesKeepID(t *testing.T) {
	root := newRoot()
	n := 0
	for _, c := range allCommands(root) {
		if !c.HasParent() || len(c.Aliases) == 0 {
			continue
		}
		parent := strings.Fields(strings.TrimPrefix(c.Parent().CommandPath(), "komando"))
		for _, a := range c.Aliases {
			got, _, err := root.Find(append(slices.Clone(parent), a))
			if err != nil || got != c || cmdID(got) != cmdID(c) {
				t.Errorf("%q by its alias %q: %v %v", c.CommandPath(), a, got, err)
				continue
			}
			n++
			if personalCmds[idKey(c)] {
				out.P.Mask = true
				startPersonal(got)
				if !personalCmd {
					t.Errorf("%s typed as %q: personal data is not hidden for an agent", c.CommandPath(), a)
				}
				out.P.Mask, personalCmd = false, false
			}
			name, _, _ := gateCheck(append(slices.Clone(parent), a), true)
			if name != cmdID(c) {
				t.Errorf("%s typed as %q: the ssh gate sees %q, want %q", c.CommandPath(), a, name, cmdID(c))
			}
		}
	}
	if n < 20 {
		t.Fatalf("only %d aliases checked", n)
	}
}

// The error envelope of a command typed by an alias names the command ID,
// as its result does.
func TestEnvelopeNamesID(t *testing.T) {
	invHome(t)
	for _, a := range []string{"x", "run"} { // exec's aliases
		code, s := runMain(t, a)
		if code != out.ExitUsage || !strings.Contains(s, `"command":"exec"`) {
			t.Errorf("%s: exit %d %s", a, code, s)
		}
	}
}

// withID keeps a renamed command's ID, and stampIDs does not overwrite it.
func TestWithIDSurvivesRename(t *testing.T) {
	c := &cobra.Command{Use: "list"}
	p := &cobra.Command{Use: "fs"}
	r := &cobra.Command{Use: "komando"}
	r.AddCommand(p)
	p.AddCommand(withID(c, "fs.ls"))
	stampIDs(r)
	if cmdID(c) != "fs.ls" || commandName(c) != "fs.ls" || idKey(c) != "fs ls" {
		t.Fatalf("ID %q", cmdID(c))
	}
	if cmdID(p) != "fs" || cmdID(r) != "komando" {
		t.Fatalf("parent IDs %q %q", cmdID(p), cmdID(r))
	}
}
