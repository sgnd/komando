//go:build !windows

package flock

import (
	"os"
	"syscall"
)

// Lock blocks until f holds an exclusive lock.
func Lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// Unlock releases the lock Lock took.
func Unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
