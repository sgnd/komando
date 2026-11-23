package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSafetyTablesPinned: every command keeps the rule-table rows and the
// TARGET kinds it had when the tables were keyed by command ID, so moving
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
		lines = append(lines, fmt.Sprintf("%s\ttarget=%q\t%s", id, targetKinds(c), strings.Join(rows, " ; ")))
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
