//go:build !darwin && !linux && !windows

package netx

// ProcessStart is "" where komando does not read a process's start time:
// a session is then known by its pid and program only.
func ProcessStart(int) string { return "" }

// startTimesKnown: this system tells komando nothing of when a process
// started.
const startTimesKnown = false
