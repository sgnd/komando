package cli

import "testing"

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
