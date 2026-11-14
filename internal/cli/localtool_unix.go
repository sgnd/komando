//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"syscall"
)

// toolSafe reports a program that only root can change: the file and every
// folder above it belong to root and no one else can write them. A link on
// the way (Linux's /bin/sh, or /bin itself) must belong to root too, and the
// file it leads to is checked the same way.
func toolSafe(_ *call, p string) bool {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	return rootsAlone(p) && rootsAlone(real)
}

// rootsAlone reports whether p and every folder above it belong to root and
// no one else can write them. A link's own mode bits are always 0777 on
// Linux and mean nothing, so only its owner is checked.
func rootsAlone(p string) bool {
	for {
		fi, err := os.Lstat(p)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return false
		}
		up := filepath.Dir(p)
		if up == p {
			return true
		}
		p = up
	}
}
