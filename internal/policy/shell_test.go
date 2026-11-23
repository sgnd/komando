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

// A crash inside the reader is a line komando cannot read, for every
// caller of Lex (the read-only check too), and Check stops the command.
func TestLexFailsClosed(t *testing.T) {
	saved := readLine
	t.Cleanup(func() { readLine = saved })
	readLine = func(*lexer) []Token { panic("boom") }
	lines, bad := Lex("uptime")
	if bad != lexFailed {
		t.Errorf("Lex after a crash: bad = %q, want %q", bad, lexFailed)
	}
	if len(lines) != 1 || len(lines[0]) != 1 || lines[0][0].Text != "uptime" {
		t.Errorf("Lex after a crash: lines = %v, want the text as one word", lines)
	}
	if hits := Check("uptime", nil); len(hits) != 1 || hits[0].ID != checkFailedID {
		t.Errorf("Check after a reader crash = %v, want one %s hit", hits, checkFailedID)
	}
}
