package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"golang.org/x/term"
)

// menuTerm is the terminal while the menu shows on it: keys arrive raw (one
// at a time, not echoed), the menu draws on the alternate screen (so the
// person's scrollback is left as it was) and the cursor is hidden. The menu
// draws on stderr, like every question komando asks, and reads stdin.
type menuTerm struct {
	in, out int
	orig    *term.State // the terminal as komando found it
	raw     bool        // the menu has the terminal raw, on the alternate screen
	pending []byte      // the start of a key whose end has not arrived yet
}

const (
	altScreenOn  = "\x1b[?1049h\x1b[?25l" // alternate screen, cursor hidden
	altScreenOff = "\x1b[?25h\x1b[?1049l"
)

func newMenuTerm() (*menuTerm, error) {
	t := &menuTerm{in: int(os.Stdin.Fd()), out: int(os.Stderr.Fd())}
	st, err := term.GetState(t.in)
	if err != nil {
		return nil, err
	}
	t.orig = st
	return t, nil
}

// enter puts the terminal in raw mode on the alternate screen. Keys typed
// while the last command ran (an Enter held a little too long) are thrown
// away, so they cannot choose something in the menu by themselves.
func (t *menuTerm) enter() error {
	if t.raw {
		return nil
	}
	if _, err := term.MakeRaw(t.in); err != nil {
		return err
	}
	t.raw, t.pending = true, nil
	_ = dropTypedAhead(t.in)
	t.write(altScreenOn)
	return nil
}

// leave puts the terminal back as komando found it: normal screen, cursor,
// line mode. It is safe to call twice, and runs on every way out (deferred).
func (t *menuTerm) leave() {
	if t.raw {
		t.write(altScreenOff)
		t.raw = false
	}
	t.restoreOrig()
}

// restoreOrig puts back the terminal modes komando started with: never the
// modes a command left behind, which may be raw if it was killed.
func (t *menuTerm) restoreOrig() { _ = term.Restore(t.in, t.orig) }

func (t *menuTerm) write(s string) { _, _ = os.Stderr.WriteString(s) }

// size is the screen's width and height, or 80x24 if it cannot be read.
func (t *menuTerm) size() (int, int) {
	w, h, err := term.GetSize(t.out)
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}

// draw puts lines on the screen from the top, clearing each line as it goes
// and everything below the last, in one write so nothing flickers. Lines
// end in \r\n because raw mode turns off the terminal's own \n handling,
// and the last one ends in nothing so the screen never scrolls. Then the
// hidden cursor goes to c, the chosen row, for magnifiers and screen readers.
func (t *menuTerm) draw(lines []string, c menuCaret) {
	var b strings.Builder
	b.WriteString("\x1b[H")
	for i, l := range lines {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString("\x1b[2K")
		b.WriteString(l)
	}
	b.WriteString("\x1b[J")
	if c.line >= 0 {
		fmt.Fprintf(&b, "\x1b[%d;%dH", c.line+1, c.col+1)
	}
	t.write(b.String())
}

// keys waits up to a quarter second for key presses. It returns none when
// the time ran out, so the caller can redraw after a resize and notice that
// komando was told to stop. Waiting with poll, not a blocked read, means no
// read is left behind to steal the keys of the command the menu runs next.
//
// A read can end inside a key (many keys queued, or a slow link): its start
// waits in pending for the rest. If nothing more comes within 30ms, it was
// the whole key: a lone ESC is the Esc key, a cut sequence is dropped.
func (t *menuTerm) keys(ctx context.Context) ([]menuKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wait := 250
	if len(t.pending) > 0 {
		wait = 30
	}
	ready, err := waitInput(t.in, wait)
	if errors.Is(err, errWaitInterrupted) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !ready {
		keys, _ := decodeKeys(t.pending, true)
		t.pending = nil
		return keys, nil
	}
	buf := make([]byte, 4096)
	m, err := os.Stdin.Read(buf)
	if err != nil {
		return nil, err
	}
	keys, rest := decodeKeys(append(t.pending, buf[:m]...), false)
	if len(rest) > 32 { // no key is this long: it is not going to end
		more, _ := decodeKeys(rest, true)
		keys, rest = append(keys, more...), nil
	}
	t.pending = slices.Clone(rest)
	return keys, nil
}
