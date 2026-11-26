package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRiskTiersPinned: for every command of today, the tier riskOf gives
// with no flag and the highest tier its rows can give, and the tier of each
// probe in whenProbes, stay as they were when riskRows was written by hand
// (cut PR B4b). Building the rows from internal/capability may reword a row;
// it must not move a tier. KOMANDO_GOLDEN_UPDATE=1 writes the file again
// (only on purpose).
func TestRiskTiersPinned(t *testing.T) {
	var lines []string
	seen := map[string]bool{}
	for _, c := range allCommands(newRoot(tcl)) {
		id := cmdID(c)
		if strings.HasPrefix(c.Name(), "__") || seen[id] {
			continue
		}
		seen[id] = true
		lines = append(lines, fmt.Sprintf("%s\tplain=%s\thighest=%s", id, riskOf(c, nil).tier, todayTier(cmdKeys[id])))
	}
	for _, p := range whenProbes {
		c, words, _ := lineWords(strings.Fields(p))
		lines = append(lines, fmt.Sprintf("probe %s\t%s", p, riskOf(c, words).tier))
	}
	slices.Sort(lines)
	got := strings.Join(lines, "\n") + "\n"
	file := filepath.Join("testdata", "risk_tiers_pinned.txt")
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
	if len(want) < 300 {
		t.Fatalf("the pin has %d lines: it no longer covers every command", len(want))
	}
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
