package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
)

// readHidden asks a person at the terminal for a value without showing it.
//
// Whatever was typed or pasted before the prompt came up (say, a password
// pasted right after pressing Enter on the command) was shown on the screen
// by the terminal in plain text, before komando could hide it, and would
// otherwise be read in silently as part of the value. It is thrown away and
// the person is told that the screen may show it.
//
// A paste of more than one line is refused: only its first line would be
// read, and the shell would run the other lines as commands once komando
// ends, showing the secret and saving it in the shell's history. The
// other lines are thrown away and nothing is used.
func readHidden(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !interrupted && dropEarlyInput(fd) {
		fmt.Fprintln(os.Stderr, "komando: text typed before this prompt was shown on the screen, so it was not used.")
		fmt.Fprintln(os.Stderr, "komando: if it was the secret, clear the screen (it may be in the scrollback) and enter it below.")
	}
	v, err := readAnswer(label, true)
	if errors.Is(err, errMoreLines) {
		return "", out.Errf(out.ExitUsage, "USAGE", "for a key or a file, use `komando secret set NAME < FILE` or pipe it",
			"the value has more than one line, so nothing was stored")
	}
	if err != nil {
		return "", err
	}
	return stripPasteMarks(v), nil
}

// interrupted: the person pressed Ctrl-C at a question in this command.
// Every later question in the command gets no answer at once: the person
// wants out, and the read that was cut short may still be waiting on the
// terminal.
var interrupted bool

// interruptedErr is what a question gives after Ctrl-C: the CANCELLED
// error ("interrupted") of a cancelled command.
func interruptedErr() error { return toErr(context.Canceled) }

// errMoreLines: more input followed a hidden answer, as a paste of several
// lines leaves it. readAnswer threw it away.
var errMoreLines = errors.New("more than one line")

// readAnswer prints label on stderr and reads one line from the terminal,
// without echo when hidden is set.
//
// komando catches Ctrl-C (SIGINT) for the whole command, so a read that
// does not watch for it would just go on waiting. readAnswer listens for
// SIGINT while it reads; on Ctrl-C it puts the terminal back as it was
// (echo on again after a hidden read), ends the line and returns
// interruptedErr. Ctrl-D (end of input) where the answer shows is an
// empty answer; the line is ended there too, as the terminal does not.
// (term.ReadPassword takes no notice of Ctrl-D.)
func readAnswer(label string, hidden bool) (string, error) {
	if interrupted {
		return "", interruptedErr()
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	defer signal.Stop(sigs)
	fd := int(os.Stdin.Fd())
	saved, err := term.GetState(fd) // nil when stdin is no terminal
	if hidden && err != nil {
		return "", err
	}
	restore := func() {
		if saved != nil {
			_ = term.Restore(fd, saved)
		}
	}
	defer restore()
	fmt.Fprint(os.Stderr, label)
	read := func() (string, error) { return bufio.NewReader(os.Stdin).ReadString('\n') }
	if hidden {
		// echo goes off before ReadPassword turns it off, so it is still
		// off after the line, while moreWaiting looks for a second one
		if err := echoOff(fd); err != nil {
			return "", err
		}
		read = func() (string, error) { b, err := term.ReadPassword(fd); return string(b), err }
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
		interrupted = true
		restore()
		fmt.Fprintln(os.Stderr)
		return "", interruptedErr()
	case a := <-got:
		if hidden {
			more := a.err == nil && moreWaiting(fd)
			restore()
			fmt.Fprintln(os.Stderr) // the Enter was not echoed
			if more {
				return "", errMoreLines
			}
		} else if errors.Is(a.err, io.EOF) {
			fmt.Fprintln(os.Stderr)
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
	if _, err := term.MakeRaw(fd); err != nil {
		return false // readAnswer restores the state it saved
	}
	time.Sleep(50 * time.Millisecond)
	n := typedAhead(fd)
	if n == 0 {
		return false
	}
	b := make([]byte, n)
	n, _ = readTTY(fd, b)
	_ = dropTypedAhead(fd)
	rest := strings.ReplaceAll(string(b[:max(n, 0)]), pasteEnd, "")
	return strings.TrimSpace(rest) != ""
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

// The marks a terminal puts around pasted text in bracketed-paste mode.
const pasteStart, pasteEnd = "\x1b[200~", "\x1b[201~"

// stripPasteMarks removes the bracketed-paste marks a terminal puts around
// pasted text when a program before komando left that mode on.
func stripPasteMarks(s string) string {
	if strings.HasPrefix(s, pasteStart) {
		s = strings.TrimSuffix(strings.TrimPrefix(s, pasteStart), pasteEnd)
	}
	return s
}
