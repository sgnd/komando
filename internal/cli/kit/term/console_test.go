package term

import "testing"

// Escape sequences count as working until Execute finds an old Windows
// console.
func TestVTOKStartsTrue(t *testing.T) {
	if !VTOK {
		t.Error("VTOK starts false")
	}
}
