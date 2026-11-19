//go:build !windows

package cli

import (
	"os"
	"syscall"
)

var forwardedSignals = []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
