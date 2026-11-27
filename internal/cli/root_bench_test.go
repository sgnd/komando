package cli

import "testing"

// BenchmarkNewRoot is the whole command tree, every command prepared:
// what `komando schema` and the tests read. The start time of the binary
// itself is measured in CI (scripts/start-time.sh).
func BenchmarkNewRoot(b *testing.B) {
	for b.Loop() {
		newRoot(tcl)
	}
}

// BenchmarkNewRootFor is what every komando call pays before it runs: the
// tree with the command of its line prepared. fake500 has 500 more leaves
// of a type the line does not name, which must cost nothing.
func BenchmarkNewRootFor(b *testing.B) {
	for _, line := range [][]string{{"version"}, {"list"}, {"storage", "s3", "object", "list"}, {"db", "query"}} {
		b.Run(line[0], func(b *testing.B) {
			for b.Loop() {
				newRootFor(tcl, line)
			}
		})
	}
	b.Run("version-fake500", func(b *testing.B) {
		fakeLeaves(b, 500)
		for b.Loop() {
			newRootFor(tcl, []string{"version"})
		}
	})
}
