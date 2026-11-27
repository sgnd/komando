package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
)

// BenchmarkMoveLeaves is the move of the safety tables that init runs once
// per moved type (BenchmarkNewRoot, in root_bench_test.go, is the tree). A
// start that got slower shows in one of the two first.
func BenchmarkMoveLeaves(b *testing.B) {
	types := slices.Clone(movedTypes)
	for b.Loop() {
		b.StopTimer()
		tablesAtStart(func() {
			b.StartTimer()
			for _, typ := range types {
				moveLeaves(typ, capability.All())
			}
			b.StopTimer()
		})
	}
}

// exampleOf answers from the leaf's own words without Find; it must give
// the answer Find gives, for every example line of every command (a line
// of an alias or of a group still goes to Find).
func TestExampleOfAgreesWithFind(t *testing.T) {
	root := newRoot(tcl)
	lines := 0
	for _, c := range allCommands(root) {
		for _, l := range strings.Split(c.Example, "\n") {
			cmd := strings.TrimSpace(exampleCommand(l))
			if !strings.HasPrefix(cmd, "komando ") || strings.ContainsAny(cmd, "|<>$`;&") {
				continue
			}
			lines++
			found, _, err := root.Find(shellWords(cmd)[1:])
			if want := err == nil && found == c; exampleOf(c, l) != want {
				t.Errorf("%s: exampleOf(%q) = %v, Find says %v", cmdID(c), l, !want, want)
			}
		}
	}
	if lines < 100 {
		t.Errorf("only %d example lines checked", lines)
	}
}
