//go:build !windows

package netx

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// programName is the file name of the program pid runs: Linux's
// /proc/PID/comm (no ps needed in small images), else ps.
func programName(pid int) (string, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		if b, err = exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output(); err != nil {
			return "", err
		}
	}
	return filepath.Base(strings.TrimSpace(string(b))), nil
}
