package term

import "testing"

// The bracketed-paste marks around a pasted value come off; a value
// without them stays as it is.
func TestStripPasteMarks(t *testing.T) {
	for in, want := range map[string]string{
		"\x1b[200~pw\x1b[201~": "pw",
		"pw":                   "pw",
		"pw\x1b[201~":          "pw\x1b[201~",
	} {
		if got := StripPasteMarks(in); got != want {
			t.Errorf("StripPasteMarks(%q) = %q, want %q", in, got, want)
		}
	}
}
