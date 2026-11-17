//go:build linux

package cli

import (
	"testing"

	"golang.org/x/sys/unix"
)

// After noPeek, komando is not dumpable.
func TestNoPeek(t *testing.T) {
	saved, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(saved), 0, 0, 0) })
	noPeek()
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || d != 0 {
		t.Errorf("dumpable %d %v", d, err)
	}
}
