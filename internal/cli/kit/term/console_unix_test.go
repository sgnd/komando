//go:build !windows

package term

import "testing"

// A Unix terminal reads escape sequences as they are: nothing is turned
// on, and the restore func is safe to call.
func TestConsoleVTUnix(t *testing.T) {
	ok, restore := ConsoleVT(-1)
	if !ok {
		t.Error("ConsoleVT: escape sequences reported off on Unix")
	}
	if restore == nil {
		t.Fatal("ConsoleVT: nil restore")
	}
	restore()
}
