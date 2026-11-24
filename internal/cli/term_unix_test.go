//go:build !windows

package cli

import "testing"

// A Unix terminal reads escape sequences as they are: nothing is turned
// on, and the restore func is safe to call.
func TestConsoleVTUnix(t *testing.T) {
	ok, restore := consoleVT(-1)
	if !ok {
		t.Error("consoleVT: escape sequences reported off on Unix")
	}
	if restore == nil {
		t.Fatal("consoleVT: nil restore")
	}
	restore()
}

// Escape sequences count as working until Execute finds an old Windows
// console.
func TestVTOKStartsTrue(t *testing.T) {
	if !vtOK {
		t.Error("vtOK starts false")
	}
}
