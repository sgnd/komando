//go:build !windows

package netx

import (
	"fmt"
	"os"
	"syscall"
)

// privateDir makes sure only this user can use the key lock folder: one
// of this user's with a wider mode is set to 0700, anyone else's is refused.
func privateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("the WireGuard key lock folder %s belongs to another user and others may write it; remove it or make it yours with mode 0700", dir)
	}
	return os.Chmod(dir, 0o700)
}
