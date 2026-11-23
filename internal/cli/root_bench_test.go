package cli

import "testing"

// BenchmarkNewRoot is what every komando call pays before it runs: today
// the whole command tree is built for each call, `komando guide guard`
// (the agent hook that runs before every tool call) included. The start
// time of the binary itself is measured in CI (scripts/start-time.sh).
func BenchmarkNewRoot(b *testing.B) {
	for b.Loop() {
		newRoot(tcl)
	}
}
