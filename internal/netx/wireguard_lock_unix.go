//go:build !windows

package netx

import (
	"fmt"
	"os"
	"syscall"
)

// privateDir makes sure only this user can use the key lock folder: a
// symlink or a folder of another user is refused, and this user's folder
// with a wider mode is set to 0700. Lstat, so a symlink is not followed.
func privateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("the WireGuard key lock folder %s is a symlink or a file, not a folder; remove it and komando makes a new one", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("the WireGuard key lock folder %s belongs to another user; remove it and komando makes a new one", dir)
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(dir, 0o700)
}
