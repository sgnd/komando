//go:build !windows

package tmpclean

import (
	"os"
	"syscall"
)

// mine: fi belongs to the user komando runs as.
func mine(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
