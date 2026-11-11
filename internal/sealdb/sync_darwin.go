package sealdb

import (
	"os"

	"golang.org/x/sys/unix"
)

// fullSync asks the drive itself to write f to disk; a plain fsync on
// macOS stops at the drive's cache.
func fullSync(f *os.File) error {
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err == nil {
		return nil
	}
	return f.Sync() // file systems without F_FULLFSYNC
}
