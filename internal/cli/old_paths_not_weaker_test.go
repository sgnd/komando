package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
)

// Before the cut, two checks tie today's tree to the v2.7 table (cut plan,
// PR B3). TestLeafNotWeaker compares rows by command ID; the two below add
// the read/change floor and compare by the path a person or agent types.

// todayHighest is the highest tier c can have today: change unless its
// kind is read, or the highest row for its key, whatever the condition.
func todayHighest(c *cobra.Command) tier {
	best := tierChange
	if k, ok := kindOf(c); ok && k.Kind == kindRead {
		best = tierRead
	}
	return max(best, todayTier(cmdKeys[cmdID(c)]))
}

// TestLeafFloorNotWeaker: every leaf, its floor included, is at least as
// strict as each command of today it carries.
func TestLeafFloorNotWeaker(t *testing.T) {
	byID := map[string]*cobra.Command{}
	for _, c := range allCommands(newRoot(tcl)) {
		byID[cmdID(c)] = c
	}
	for _, l := range capability.All() {
		for _, id := range slices.Concat(l.Today, l.Carries) {
			c, ok := byID[id]
			if !ok {
				t.Errorf("%s: carries %s, which is no command", l.Key, id)
				continue
			}
			want, got := todayHighest(c), capability.Highest(l.Key)
			if int(got) >= int(want) {
				continue
			}
			if _, ok := notWeakerExceptions[l.Key.String()+" | "+id]; ok {
				continue
			}
			t.Errorf("%s: carries %s, which is %s today, but the leaf is at most %s", l.Key, id, want, tier(got))
		}
	}
}

// TestOldPathsNotWeaker: for every path of today as typed, with every
// alias, the v2.7 table finds no command, or a leaf whose highest tier is
// at least today's; and where that leaf keeps a command of today's key,
// the ssh gate refuses it for every key that is refused the old path.
func TestOldPathsNotWeaker(t *testing.T) {
	invHome(t)
	gateInventory(t)
	root := newRoot(tcl)
	byID := map[string]*cobra.Command{}
	for _, c := range allCommands(root) {
		byID[cmdID(c)] = c
	}
	keys := []gateKey{readKey, netReadKey, fullKey, shellAccessKey}
	n, matched, gated := 0, 0, 0
	for _, typed := range typedPaths(root) {
		old, _, err := root.Find(typed)
		if err != nil || old == root {
			continue
		}
		n++
		l, found := tableLeaf(typed)
		if !found {
			continue // no command: a person's step for an agent (B2), refused at the gate (B1)
		}
		matched++
		if got, want := capability.Highest(l.Key), todayHighest(old); int(got) < int(want) {
			if _, ok := notWeakerExceptions[l.Key.String()+" | "+cmdID(old)]; !ok {
				t.Errorf("%q: today %s (%s), in v2.7 the leaf %s, at most %s", strings.Join(typed, " "), cmdID(old), want, l.Key, tier(got))
			}
		}
		if len(l.Today) == 0 {
			continue // no command of today has the leaf's key: the gate refuses it (fails closed)
		}
		gated++
		kept := byID[l.Today[0]]
		for _, k := range keys {
			_, _, before := gateCheck(slices.Clone(typed), k)
			_, _, after := gateCheck(strings.Fields(strings.TrimPrefix(kept.CommandPath(), "komando")), k)
			if before != nil && after == nil {
				t.Errorf("%q %+v: the gate refuses it today (%s), but runs the v2.7 leaf %s", strings.Join(typed, " "), k, before.Code, l.Key)
			}
		}
	}
	t.Logf("%d typed paths: %d find a v2.7 leaf, %d of those through the gate", n, matched, gated)
	if matched == 0 || gated == 0 {
		t.Errorf("no typed path finds a v2.7 leaf (%d) or reaches the gate check (%d): the test checks nothing", matched, gated)
	}
	if n < len(byID)-1 {
		t.Errorf("%d typed paths checked for %d commands: the walk missed some", n, len(byID))
	}
}

// typedPaths are the command words of every command of today, under each
// of its names and its parents' names (aliases and plurals included).
func typedPaths(root *cobra.Command) [][]string {
	var out [][]string
	var walk func(c *cobra.Command, prefix []string)
	walk = func(c *cobra.Command, prefix []string) {
		for _, s := range c.Commands() {
			if strings.HasPrefix(s.Name(), "__") {
				continue
			}
			for _, name := range append([]string{s.Name()}, s.Aliases...) {
				p := append(slices.Clone(prefix), name)
				out = append(out, p)
				walk(s, p)
			}
		}
	}
	walk(root, nil)
	return out
}

// tableLeaf is the built leaf the v2.7 tree would run for words: the leaf
// whose path (its verb or one of its synonyms last) is the longest prefix
// of words; the words after it are arguments.
func tableLeaf(words []string) (capability.Leaf, bool) {
	var best capability.Leaf
	bestLen := 0
	for _, l := range capability.All() {
		if l.State != capability.Built {
			continue
		}
		p := l.Path()
		for _, verb := range append([]string{l.Verb}, l.Synonyms...) {
			path := append(slices.Clone(p[:len(p)-1]), verb)
			if len(path) > bestLen && len(path) <= len(words) && slices.Equal(path, words[:len(path)]) {
				best, bestLen = l, len(path)
			}
		}
	}
	return best, bestLen > 0
}
