package term

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	xterm "golang.org/x/term"
)

// ErrMoreLines: more input followed a hidden answer, as a paste of several
// lines leaves it. ReadAnswer threw it away.
var ErrMoreLines = errors.New("more than one line")

// ReadAnswer prints label on errw and reads one line from in,
// without echo when hidden is set.
//
// komando catches Ctrl-C (SIGINT) for the whole command, so a read that
// does not watch for it would just go on waiting. ReadAnswer listens for
// SIGINT while it reads; on Ctrl-C it puts the terminal back as it was
// (echo on again after a hidden read), ends the line and returns
// Interrupted. Ctrl-D (end of input) where the answer shows is an
// empty answer; the line is ended there too, as the terminal does not.
// (x/term's ReadPassword takes no notice of Ctrl-D.)
func ReadAnswer(in io.Reader, errw io.Writer, interrupted *bool, label string, hidden bool) (string, error) {
	if *interrupted {
		return "", Interrupted()
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	fd := int(os.Stdin.Fd())
	saved, err := xterm.GetState(fd) // nil when stdin is no terminal
	if hidden && err != nil {
		return "", err
	}
	restore := func() {
		if saved != nil {
			_ = xterm.Restore(fd, saved)
		}
	}
	defer restore()
	fmt.Fprint(errw, label)
	read := func() (string, error) { return bufio.NewReader(in).ReadString('\n') }
	if hidden {
		// echo goes off before ReadPassword turns it off, so it is still
		// off after the line, while moreWaiting looks for a second one
		if err := echoOff(fd); err != nil {
			return "", err
		}
		read = func() (string, error) { b, err := xterm.ReadPassword(fd); return string(b), err }
	}
	type answer struct {
		s   string
		err error
	}
	got := make(chan answer, 1)
	go func() { // left behind on Ctrl-C; it ends with the command
		s, err := read()
		got <- answer{s, err}
	}()
	select {
	case <-sigs:
		*interrupted = true
		restore()
		fmt.Fprintln(errw)
		return "", Interrupted()
	case a := <-got:
		if hidden {
			more := a.err == nil && moreWaiting(fd)
			restore()
			fmt.Fprintln(errw) // the Enter was not echoed
			if more {
				return "", ErrMoreLines
			}
		} else if errors.Is(a.err, io.EOF) {
			fmt.Fprintln(errw)
			return "", nil
		}
		return a.s, a.err
	}
}

// moreWaiting says whether input waits after a hidden line, as a paste of
// several lines leaves it, and throws it away, so the shell does not run it
// once komando ends. Line mode counts only finished lines, and a paste may
// still be arriving, so it looks without line mode (and echo) for a moment.
// Empty lines and a bracketed paste's end mark alone do not count.
func moreWaiting(fd int) bool {
	if _, err := xterm.MakeRaw(fd); err != nil {
		return false // ReadAnswer restores the state it saved
	}
	time.Sleep(50 * time.Millisecond)
	n := TypedAhead(fd)
	if n == 0 {
		return false
	}
	b := make([]byte, n)
	n, _ = readTTY(fd, b)
	_ = dropTypedAhead(fd)
	rest := strings.ReplaceAll(string(b[:max(n, 0)]), pasteEnd, "")
	return strings.TrimSpace(rest) != ""
}

// DropEarlyInput throws away what was typed before the prompt, and says
// whether there was any. A terminal in line mode counts only finished lines
// as waiting, so it looks with line mode (and echo) off for a moment.
func DropEarlyInput(fd int) bool {
	old, err := xterm.MakeRaw(fd)
	if err != nil {
		return false
	}
	defer xterm.Restore(fd, old)
	if TypedAhead(fd) == 0 {
		return false
	}
	_ = dropTypedAhead(fd)
	return true
}

// The marks a terminal puts around pasted text in bracketed-paste mode.
const pasteStart, pasteEnd = "\x1b[200~", "\x1b[201~"

// StripPasteMarks removes the bracketed-paste marks a terminal puts around
// pasted text when a program before komando left that mode on.
func StripPasteMarks(s string) string {
	if strings.HasPrefix(s, pasteStart) {
		s = strings.TrimSuffix(strings.TrimPrefix(s, pasteStart), pasteEnd)
	}
	return s
}
