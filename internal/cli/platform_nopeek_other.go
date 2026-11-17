//go:build !linux

package cli

// noPeek is Linux only: macOS lets no unsigned process attach to another
// without the person's consent, and on Windows a process of the same user
// can always read another's memory.
func noPeek() {}
