//go:build unix

package term

import (
	"os"
	"syscall"
	"time"
)

// raise sends s to this process.
func raise(s os.Signal) {
	if sig, ok := s.(syscall.Signal); ok {
		_ = syscall.Kill(os.Getpid(), sig)
		time.Sleep(time.Second) // delivered at once; the caller's exit is the fallback
	}
}
