//go:build !windows

package sshx

import "syscall"

// errRefused is the error number of a refused connection.
var errRefused error = syscall.ECONNREFUSED
