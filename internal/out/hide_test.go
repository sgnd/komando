package out

import (
	"strings"
	"testing"
)

// C186: a vault or added value that is a short plain word ("shared", an
// L2TP pre-shared key in the tests) is not hidden wherever that word
// appears in komando's own notes. A longer value, or one with a digit or
// a symbol, is still hidden, and the patterns still hide a short word
// given as a password.
func TestPlainWordValuesStayVisible(t *testing.T) {
	p := &Printer{Mask: true, Secrets: func() map[string]string {
		return map[string]string{"office-psk": "shared", "long": "correcthorsebattery", "mixed": "shar3d"}
	}}
	p.AddValue("Shared")
	const note = "Would stop office-2 only: it is in a shared session with office."
	if got := p.Redact(note); got != note {
		t.Errorf("note: %q", got)
	}
	tests := []struct{ name, in, want string }{
		{"a long word value", "x correcthorsebattery y", "x [secret:long] y"},
		{"a value with a digit", "x shar3d y", "x [secret:mixed] y"},
		{"a short word as a password", "password=shared", "password=" + Hidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Redact(tt.in); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	if p.HoldsVaultValue("a shared session") {
		t.Error("HoldsVaultValue: a plain word counts as a vault value")
	}
	if !strings.Contains(string(p.redactJSON([]byte(`{"v":"correcthorsebattery"}`))), "[secret:long]") {
		t.Error("JSON: a long word value is shown")
	}
}
