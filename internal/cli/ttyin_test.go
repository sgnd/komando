package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

// After Ctrl-C at one question, every later question in the command gets
// no answer at once, and nothing reads the terminal again. The next command
// (newRoot) asks again.
func TestAskAfterInterrupt(t *testing.T) {
	tcl.interrupted = true
	defer func() { tcl.interrupted = false }()
	if a := ask(tcl, "Continue? [y/N] "); a != "" {
		t.Errorf("ask: %q", a)
	}
	if _, err := readHidden(tcl, "Password: "); toErr(err).Code != "CANCELLED" {
		t.Errorf("readHidden: %v", err)
	}
	if newRoot(tcl); tcl.interrupted {
		t.Error("the next command starts with the interrupt still set")
	}
}

// A VPN server's prompt keeps its lines, loses control characters, and
// ends where the person types.
func TestVpnQuestion(t *testing.T) {
	cases := map[string]string{
		"Password:":  "Password: ",
		"Token code": "Token code: ",
		"Authorized use only.\r\n\x1b]0;owned\x07Be nice.\nAccept the sign-in notice? [y/N]":   "Authorized use only.\n]0;ownedBe nice.\nAccept the sign-in notice? [y/N] ",
		"The VPN offers more than one realm:\n  1  Users\n  2  Admins\nRealm (number or name)": "The VPN offers more than one realm:\n  1  Users\n  2  Admins\nRealm (number or name): ",
		"Enter the code\u202e from the app?":                                                   "Enter the code from the app? ",
	}
	for label, want := range cases {
		if got := loginQuestion(label); got != want {
			t.Errorf("%q: got %q, want %q", label, got, want)
		}
	}
}

// readAnswerWith runs readAnswer with stdin holding in, and gives the
// answer, the error and what it printed on stderr.
func readAnswerWith(t *testing.T, in, label string, hidden bool) (string, error, string) {
	t.Helper()
	var errw bytes.Buffer
	savedIn, savedErr := tcl.stdin, tcl.out.Err
	tcl.stdin, tcl.out.Err = strings.NewReader(in), &errw
	defer func() { tcl.stdin, tcl.out.Err = savedIn, savedErr }()
	a, err := readAnswer(tcl, label, hidden)
	return a, err, errw.String()
}

// A shown answer is the line as typed, Enter included; the question goes
// to stderr.
func TestReadAnswerLine(t *testing.T) {
	a, err, shown := readAnswerWith(t, "yes\nmore\n", "Go on? ", false)
	if a != "yes\n" || err != nil || shown != "Go on? " {
		t.Errorf("got %q, %v, shown %q", a, err, shown)
	}
}

// Ctrl-D (end of input) where the answer shows is an empty answer, and the
// line is ended, as the terminal does not.
func TestReadAnswerEndOfInput(t *testing.T) {
	a, err, shown := readAnswerWith(t, "", "Go on? ", false)
	if a != "" || err != nil || shown != "Go on? \n" {
		t.Errorf("got %q, %v, shown %q", a, err, shown)
	}
}

// After a Ctrl-C, readAnswer asks nothing and reads nothing.
func TestReadAnswerAfterInterrupt(t *testing.T) {
	tcl.interrupted = true
	defer func() { tcl.interrupted = false }()
	a, err, shown := readAnswerWith(t, "yes\n", "Go on? ", false)
	if a != "" || toErr(err).Code != "CANCELLED" || shown != "" {
		t.Errorf("got %q, %v, shown %q", a, err, shown)
	}
}

// A hidden answer needs a terminal: without one it fails before the
// question shows, so a secret is never read from a pipe with echo on.
func TestReadAnswerHiddenNeedsTerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal here")
	}
	a, err, shown := readAnswerWith(t, "secret\n", "Password: ", true)
	if a != "" || err == nil || shown != "" {
		t.Errorf("got %q, %v, shown %q", a, err, shown)
	}
}
