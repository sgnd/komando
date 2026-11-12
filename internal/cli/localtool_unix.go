//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"syscall"
)

// toolSafe reports a program that only root can change: the file and every
// folder above it belong to root and no one else can write them.
func toolSafe(p string) bool {
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return false
		}
		up := filepath.Dir(p)
		if up == p {
			return true
		}
		p = up
	}
}
