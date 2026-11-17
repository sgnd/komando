package netx

import (
	"bytes"
	"testing"
)

// The browser sign-in's notices go to the writer of the command that logs
// in (its call's stderr), never the process's, without the control
// characters a server may have put in them.
func TestSignInNoticeGoesToTheCall(t *testing.T) {
	var b bytes.Buffer
	signInNotice(&b)("open the page\x1b[2J at https://vpn.example\u202e")
	if got, want := b.String(), "komando: open the page[2J at https://vpn.example\n"; got != want {
		t.Errorf("notice: %q, want %q", got, want)
	}
	signInNotice(nil)("nobody reads this") // no writer: nothing, and no panic
}
