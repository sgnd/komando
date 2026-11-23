package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSafetyTablesPinned: every command keeps the rule-table rows, the
// kind (read, change, depends) and the TARGET kinds it had when the tables were keyed by command ID, so moving
// the key to (type, area, verb) changes nothing a person or an agent sees.
// KOMANDO_GOLDEN_UPDATE=1 writes the file again (only on purpose).
func TestSafetyTablesPinned(t *testing.T) {
	var lines []string
	seen := map[string]bool{}
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		if strings.HasPrefix(c.Name(), "__") || seen[id] {
			continue
		}
		seen[id] = true
		var rows []string
		for _, r := range rowsFor(c) {
			rows = append(rows, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", r.tier, r.cond, r.what, r.dynamic, r.bulk, r.typed, r.items))
		}
		kind := "none"
		if k, ok := kindOf(c); ok {
			kind = k.Kind + "|" + k.Note
		}
		lines = append(lines, fmt.Sprintf("%s\tkind=%s\ttarget=%q\t%s", id, kind, targetKinds(c), strings.Join(rows, " ; ")))
	}
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	file := filepath.Join("testdata", "safety_tables_pinned.txt")
	if os.Getenv("KOMANDO_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	for _, l := range lines {
		if !slices.Contains(want, l) {
			t.Errorf("changed or new: %s", l)
		}
	}
	for _, l := range want {
		if !slices.Contains(lines, l) {
			t.Errorf("gone: %s", l)
		}
	}
}

// TestSafetyKeys: every command has a (type, area, verb) key and no two
// share one, every rule-table row names a command's key, and every shell
// (host, database, cluster) is for a person only (spec section 7.1).
func TestSafetyKeys(t *testing.T) {
	root := newRoot(tcl)
	inTree := map[string]bool{}
	for _, c := range allCommands(root) {
		if strings.HasPrefix(c.Name(), "__") {
			continue // cobra's completion plumbing
		}
		id := cmdID(c)
		inTree[id] = true
		if _, ok := cmdKeys[id]; !ok {
			t.Errorf("command %s has no key in cmdKeys, so no row can give it a tier", id)
		}
	}
	for id := range cmdKeys {
		if !inTree[id] {
			t.Errorf("cmdKeys has %s, which is no command ID", id)
		}
	}
	if len(keyIDs) != len(cmdKeys) {
		t.Errorf("%d commands share %d keys: two commands would share their rows", len(cmdKeys), len(keyIDs))
	}
	for i, r := range riskRows {
		if _, ok := keyIDs[r.key]; !ok {
			t.Errorf("riskRows[%d] (%s) names the key %v, which no command has", i, r.id, r.key)
		}
	}
	shells := 0
	for _, c := range allCommands(root) {
		if k := cmdKeys[cmdID(c)]; k.verb == "shell" {
			shells++
			if got := riskOf(c, nil).tier; got != tierPerson {
				t.Errorf("%s (%v) is %s, want person", cmdID(c), k, got)
			}
		}
	}
	if shells < 3 {
		t.Errorf("%d shells, want host, database and cluster", shells)
	}
}
