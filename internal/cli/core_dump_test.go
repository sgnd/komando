//go:build !windows

package cli

import (
	"syscall"
	"testing"
)

// A crash dump of komando would hold vault values and the store's key
// (Go strings cannot be wiped): komando turns core files off for itself.
func TestNoCoreDumps(t *testing.T) {
	var saved syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &saved); err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_CORE, &saved) })
	l := saved
	l.Cur = l.Max
	if l.Cur == 0 {
		t.Skip("core files are already off here")
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &l); err != nil {
		t.Skip(err)
	}
	noCoreDumps()
	var now syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &now); err != nil || now.Cur != 0 {
		t.Errorf("core file limit %d (%v), want 0", now.Cur, err)
	}
}
