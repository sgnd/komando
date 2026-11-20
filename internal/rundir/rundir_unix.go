//go:build !windows

package rundir

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Check refuses dir unless it is a folder (Lstat: a link is not
// followed) of this user that only this user may open (0700).
func Check(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("komando's run folder %s is a link or a file, not a folder; remove it and komando makes a new one", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("komando's run folder %s belongs to another user; remove it and komando makes a new one", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("komando's run folder %s may be opened by other users (mode %o); run `chmod 700 %s`", dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// create opens path O_EXCL (an existing name or link is never opened),
// mode 0600 in a 0700 folder: no other user may open it.
func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

// Free is the space in dir's file system this user may write.
func Free(dir string) (uint64, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(dir, &s); err != nil {
		return 0, err
	}
	return uint64(s.Bavail) * uint64(s.Bsize), nil //nolint:gosec // block counts and sizes are never negative
}
