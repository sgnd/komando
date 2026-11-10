//go:build windows

package flock

import (
	"os"

	"golang.org/x/sys/windows"
)

// whole covers the full file range, as flock does.
const whole = ^uint32(0)

// Lock blocks until f holds an exclusive lock.
func Lock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, whole, whole, ol)
}

// Unlock releases the lock Lock took.
func Unlock(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, whole, whole, ol)
}
