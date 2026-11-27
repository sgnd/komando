//go:build !windows

package gatehere

import (
	"io/fs"
	"syscall"
)

// links is how many names (hardlinks) the file has.
func links(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}
