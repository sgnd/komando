//go:build !windows

package netx

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Alive reports whether a process exists.
func Alive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM) // EPERM: alive, owned by root
}

// Terminate asks one process to stop. It refuses every pid that is not a
// single other process: kill(-1) would signal every program of the user,
// kill(0) the whole process group, kill(1) init.
func Terminate(pid int) error {
	if pid <= 1 || pid == os.Getpid() {
		return fmt.Errorf("refusing to signal pid %d", pid)
	}
	return syscall.Kill(pid, syscall.SIGTERM)
}
