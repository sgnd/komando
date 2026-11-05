package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// readHidden asks a person at the terminal for a value without showing it.
//
// Whatever was typed or pasted before the prompt came up (say, a password
// pasted right after pressing Enter on the command) was shown on the screen
// by the terminal in plain text, before komando could hide it, and would
// otherwise be read in silently as part of the value. It is thrown away and
// the person is told, so the value is always what was entered after the
// prompt, and the person knows the screen may show the earlier text.
func readHidden(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if dropEarlyInput(fd) {
		fmt.Fprintln(os.Stderr, "komando: text typed before this prompt was shown on the screen, so it was not used.")
		fmt.Fprintln(os.Stderr, "komando: if it was the secret, clear the screen (it may be in the scrollback) and enter it below.")
	}
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return stripPasteMarks(string(b)), nil
}

// dropEarlyInput throws away what was typed before the prompt, and says
// whether there was any. A terminal in line mode counts only finished lines
// as waiting, so it looks with line mode (and echo) off for a moment.
func dropEarlyInput(fd int) bool {
	old, err := term.MakeRaw(fd)
	if err != nil {
		return false
	}
	defer term.Restore(fd, old)
	if typedAhead(fd) == 0 {
		return false
	}
	_ = dropTypedAhead(fd)
	return true
}

// stripPasteMarks removes the bracketed-paste marks a terminal puts around
// pasted text when a program before komando left that mode on.
func stripPasteMarks(s string) string {
	if strings.HasPrefix(s, "\x1b[200~") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "\x1b[200~"), "\x1b[201~")
	}
	return s
}
