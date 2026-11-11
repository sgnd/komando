package store

import "sync/atomic"

// commits counts the write steps of this process that changed komando's
// store: a sealed write step that committed a change, or a saved
// state.json. A command compares it with the count at its start to know
// whether it already changed something (the CLI's "nothing was changed").
var commits atomic.Uint64

// Commits is how many write steps of this process changed the store.
func Commits() uint64 { return commits.Load() }

// committed is the sealed store's OnGeneration: a write step committed a
// change.
func committed(gen uint64) {
	commits.Add(1)
	raiseGeneration(gen)
}
