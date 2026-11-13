package cli

import (
	"strings"
	"testing"
)

// stripVT takes out escape sequences: CSI (ESC [ ... final), OSC (ESC ]
// ... BEL or ESC \) and two-byte ones (ESC x). A cursor move to another
// line becomes a line break, so a test can still tell lines apart.
func stripVT(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '[':
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) && (s[j] == 'H' || s[j] == 'E') {
				b.WriteByte('\n')
			}
			i = j
		case ']':
			j := i + 2
			for j < len(s) && s[j] != 0x07 && !(s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\') {
				j++
			}
			if j < len(s) && s[j] == 0x1b {
				j++
			}
			i = j
		default:
			i++
		}
	}
	return b.String()
}

func TestStripVT(t *testing.T) {
	got := stripVT("\x1b[?25l\x1b[2J\x1b[mweb (protected)\x1b[1;1H\x1b]0;komando\x07[y/N] \x1b[K")
	if got != "web (protected)\n[y/N] " {
		t.Errorf("stripVT = %q", got)
	}
}
