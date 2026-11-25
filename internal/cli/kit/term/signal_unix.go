//go:build unix

package term

import (
	"os"
	"syscall"
	"time"
)

// Raise sends s to this process. The caller resets its handler for s
// first (signal.Reset), so the process ends of it, as it would have
// without a handler.
func Raise(s os.Signal) {
	if sig, ok := s.(syscall.Signal); ok {
		_ = syscall.Kill(os.Getpid(), sig)
		time.Sleep(time.Second) // delivered at once; the caller's exit is the fallback
	}
}
