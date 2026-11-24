package cli

import "testing"

// Escape sequences count as working until Execute finds an old Windows
// console.
func TestVTOKStartsTrue(t *testing.T) {
	if !vtOK {
		t.Error("vtOK starts false")
	}
}
