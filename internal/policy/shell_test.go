package policy

import (
	"testing"
)

// Input the lexer cannot read ends in a reason, never a crash: an
// unclosed `, ' or $' inside "..." once read past the end of the line.
func TestLexMalformedInput(t *testing.T) {
	for _, s := range []string{
		"AAAA $(A \"0`0000000000000000",
		"\"`",
		"echo \"`ls",
		"echo \"$(echo `x\"",
		"`",
		"echo `a \"`b",
		"\"$('0",
		"\"$(echo 'x",
		"\"$(echo \\",
		"\"$(echo $'x",
	} {
		_, bad := Lex(s)
		if bad == "" {
			t.Errorf("Lex(%q): want a reason it cannot read it", s)
		}
	}
}
