//go:build linux

package cli

import "golang.org/x/sys/unix"

// noPeek makes komando not dumpable on Linux: another process of the same
// user (an AI agent's shell among them) can then neither attach to it
// (ptrace) nor read its memory or environment through /proc, where vault
// values, the store's key and passwords sit as Go strings. komando itself
// still reads its own /proc/self. A program komando starts is dumpable
// again once it runs (exec resets it), so nothing it runs is affected.
func noPeek() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
