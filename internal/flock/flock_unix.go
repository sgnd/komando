//go:build !windows

package flock

import (
	"errors"
	"os"
	"syscall"
)

// Lock blocks until f holds an exclusive lock.
func Lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

// Unlock releases the lock Lock took.
func Unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// TryLock takes the lock only if no other process holds it; ok is false
// when one does.
func TryLock(f *os.File) (ok bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
