package cli

import (
	"errors"
	"fmt"
	"os"

	kitterm "github.com/sgnd/komando/internal/cli/kit/term"
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
func readHidden(cl *call, label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !cl.interrupted && kitterm.DropEarlyInput(fd) {
		fmt.Fprintln(cl.out.Err, "Note: what was typed before this question showed was not used.")
		sayLine(cl, "If it was the secret, clear the screen (it may be in the scrollback), then type it below.")
	}
	v, err := readAnswer(cl, label, true)
	if errors.Is(err, kitterm.ErrMoreLines) {
		return "", out.Errf(out.ExitUsage, "USAGE", "for a key or a file, use `komando secret set NAME < FILE` or pipe it",
			"the value has more than one line, so nothing was stored")
	}
	if err != nil {
		return "", err
	}
	return kitterm.StripPasteMarks(v), nil
}

// readAnswer prints label on stderr and reads one line from the terminal,
// without echo when hidden is set: term.ReadAnswer has the rules. It notes
// the question for the guard first, and is the only caller of
// term.ReadAnswer (TestReadAnswerOnlyThroughTheWrapper).
func readAnswer(cl *call, label string, hidden bool) (string, error) {
	noteAsk(cl, "terminal question")
	return kitterm.ReadAnswer(cl.stdin, cl.out.Err, &cl.interrupted, label, hidden)
}
