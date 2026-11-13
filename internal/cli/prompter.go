package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
)

// A person at a terminal who leaves out what a command needs is asked for
// it, one line at a time, in the normal screen (the scrollback keeps it):
// `CONN (database):` with a numbered list of the databases komando knows,
// `--old:` for a flag. Nobody else is ever asked: an AI agent, a script, a
// pipe, CI, TERM=dumb and JSON output get the usage error they always got
// (docs/design/principles.md, section 11).

// promptable says whether komando may ask: stdin, stdout and stderr are
// terminals, no AI agent runs it, it is not CI, the terminal is not dumb
// and the output is text (format is what -o or KOMANDO_OUTPUT asked for).
// Every question checks it; no command looks at the terminal on its own.
var promptable = func(cl *call, format string) bool {
	return cl.terminal && isTerminal(cl.out.W) && promptGate(format, cl.isAgent(), cl.getenv("CI"), cl.getenv("TERM"))
}

// promptGate is promptable without the terminal checks, so tests can try
// each condition.
func promptGate(format string, agent bool, ci, termName string) bool {
	ciOn := ci != "" && ci != "false" && ci != "0"
	return !agent && !ciOn && termName != "dumb" && (format == "" || format == "auto" || format == "text")
}

// promptW is where cl's questions are drawn: the call's stderr.
// promptRead reads one answer. Tests stand in for both.
var (
	promptW    = func(cl *call) io.Writer { return cl.out.Err }
	promptRead = func(cl *call, label string) (string, error) { return promptLineIdle(cl, label, promptIdle) }
)

// promptIdle: a question nobody answers for this long is given up, so a
// program that looks like a person cannot hang on it forever.
const promptIdle = 10 * time.Minute

// errPromptCancel: the person stopped at a question (Ctrl-C, an empty
// answer where one was needed three times, no answer for promptIdle).
var errPromptCancel = errors.New("cancelled at a question")

// promptLineIdle reads one line from the terminal, or gives up after idle.
func promptLineIdle(cl *call, label string, idle time.Duration) (string, error) {
	type answer struct {
		s   string
		err error
	}
	got := make(chan answer, 1)
	go func() { s, err := readAnswer(cl, label, false); got <- answer{s, err} }()
	select {
	case a := <-got:
		return a.s, a.err
	case <-time.After(idle):
		fmt.Fprintln(promptW(cl))
		return "", errPromptCancel
	}
}

func promptLine(cl *call, label string) (string, error) {
	if !cl.promptOn {
		if testing.Testing() {
			panic("a question was asked without a person at a terminal")
		}
		return "", out.Usage("komando cannot ask here: give every argument on the command line")
	}
	read := promptRead
	if mask := cl.promptMask; mask != nil {
		read = func(cl *call, label string) (string, error) { return promptReadMasked(cl, label, mask) }
	}
	s, err := read(cl, label)
	if err != nil {
		if errors.Is(err, errPromptCancel) {
			return "", err
		}
		return "", errPromptCancel
	}
	return strings.TrimSpace(s), nil
}

// promptQ is one question: its label is the real name (CONN, --old), help
// is shown when the person types ?.
type promptQ struct {
	label, help, def string
	optional         bool
	check            func(v string) string
}

// promptHelp prints a question's help, for ?.
func promptHelp(cl *call, q promptQ) {
	if q.help == "" {
		fmt.Fprintln(promptW(cl), "  (no more help: type the value, or press Ctrl-C to stop)")
		return
	}
	for _, l := range pickWrap(q.help, 76) {
		fmt.Fprintln(promptW(cl), "  "+l)
	}
}

// promptTries is how many wrong answers a question takes before it stops.
const promptTries = 3

// askText asks for a typed value: Enter takes the default, ? shows the
// help, a wrong answer says why and asks again.
func askText(cl *call, q promptQ) (string, error) {
	label := q.label
	if q.def != "" {
		label += " [" + q.def + "]"
	}
	for try := 0; try < promptTries; {
		v, err := promptLine(cl, label+": ")
		if err != nil {
			return "", err
		}
		if v == "?" {
			promptHelp(cl, q)
			continue
		}
		if v == "" {
			v = q.def
		}
		problem := ""
		switch {
		case v == "" && !q.optional:
			problem = "this one is needed (? explains it, Ctrl-C stops)"
		case v != "" && q.check != nil:
			problem = q.check(v)
		}
		if problem == "" {
			return v, nil
		}
		fmt.Fprintln(promptW(cl), "  ! "+problem)
		try++
	}
	return "", errPromptCancel
}

// askPick asks for one of rows by its number, or its value typed; other
// text narrows the list (free: it is taken as typed, as a selector like
// @web or tag:db, or a new name, is). Enter takes the default.
func askPick(cl *call, q promptQ, rows []pickRow, free bool) (string, error) {
	shown := rows
	promptRows(cl, shown)
	shownDef := q.def
	for _, r := range rows {
		if r.value == q.def && q.def != "" {
			shownDef = r.label // the default as the list names it
		}
	}
	for try := 0; try < promptTries; {
		label := q.label
		if shownDef != "" {
			label += " [" + shownDef + "]"
		}
		v, err := promptLine(cl, label+": ")
		if err != nil {
			return "", err
		}
		switch {
		case v == "?":
			promptHelp(cl, q)
			continue
		case v == "" && q.def != "":
			return q.def, nil
		case v == "" && q.optional:
			return "", nil
		case v == "":
		default:
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(shown) {
				return shown[n-1].value, nil
			}
			for _, r := range rows {
				if r.value == v {
					return v, nil
				}
			}
			if free {
				if q.check != nil {
					if p := q.check(v); p != "" {
						fmt.Fprintln(promptW(cl), "  ! "+p)
						try++
						continue
					}
				}
				return v, nil
			}
			var match []pickRow
			for _, r := range rows {
				if strings.Contains(strings.ToLower(r.label+" "+r.detail), strings.ToLower(v)) {
					match = append(match, r)
				}
			}
			if len(match) == 1 {
				return match[0].value, nil
			}
			if len(match) > 1 {
				shown = match
				promptRows(cl, shown)
				continue
			}
		}
		fmt.Fprintln(promptW(cl), "  ! type a number from the list (? explains it, Ctrl-C stops)")
		try++
	}
	return "", errPromptCancel
}

// promptMaxRows is how many rows a list shows at once; typing narrows it.
const promptMaxRows = 30

// promptRows prints a numbered list, its names and details in columns.
func promptRows(cl *call, rows []pickRow) {
	w := 0
	for _, r := range rows[:min(len(rows), promptMaxRows)] {
		w = max(w, displayWidth(r.label))
	}
	for i, r := range rows[:min(len(rows), promptMaxRows)] {
		line := fmt.Sprintf("  %2d  %s", i+1, cleanText(r.label))
		if r.detail != "" {
			line += strings.Repeat(" ", w-displayWidth(r.label)+2) + cleanText(r.detail)
		}
		fmt.Fprintln(promptW(cl), line)
	}
	if len(rows) > promptMaxRows {
		fmt.Fprintf(promptW(cl), "  ... %d more: type part of a name to narrow the list\n", len(rows)-promptMaxRows)
	}
}

// askRun asks whether a command that komando filled in runs: y runs it,
// d runs it with --dry-run first (and asks again), anything else is no.
func askRun(cl *call) (string, error) {
	v, err := promptLine(cl, "Run it? [y/N, d = --dry-run first]: ")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(v) {
	case "y", "yes":
		return "y", nil
	case "d":
		return "d", nil
	}
	return "n", nil
}

// askTypeName asks the person to type want (shown as typedAnswer shows it)
// to go on with something that cannot be undone; a wrong answer is a no.
func askTypeName(cl *call, want, shown string) (bool, error) {
	v, err := promptLine(cl, "Type "+shown+" to continue: ")
	if err != nil {
		return false, err
	}
	return want != "" && v == want, nil
}

// promptReadMasked reads one line drawn through mask as it is typed (a
// password pasted with an address is never drawn); tests stand in for it.
var promptReadMasked = readMaskedLine

// askMasked is askText for a line that may hold a pasted password: the
// screen shows it through mask, never as typed.
func askMasked(cl *call, q promptQ, mask func(string) string) (string, error) {
	if !cl.promptOn {
		return askText(cl, q) // askText says what is wrong
	}
	cl.promptMask = mask
	defer func() { cl.promptMask = nil }()
	return askText(cl, q)
}

// readMaskedLine reads a line in raw mode, drawing it through mask after
// every key or paste. Ctrl-C stops (as at any question), Ctrl-U clears,
// Backspace takes one character back; other control keys are ignored.
func readMaskedLine(cl *call, label string, mask func(string) string) (string, error) {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return readAnswer(cl, label, false)
	}
	defer func() { _ = term.Restore(fd, old) }()
	var line []rune
	drawn := 0 // characters on the line, for a console without escape sequences
	draw := func() {
		shown := label + mask(string(line))
		if vtOK {
			fmt.Fprint(promptW(cl), "\r\x1b[2K"+shown)
			return
		}
		fmt.Fprint(promptW(cl), "\r"+maskedRedraw(shown, drawn))
		drawn = utf8.RuneCountInString(shown)
	}
	draw()
	buf := make([]byte, 4096)
	for {
		n, err := cl.stdin.Read(buf)
		if err != nil {
			return "", err
		}
		b := buf[:n]
		for len(b) > 0 {
			switch c := b[0]; {
			case c == 3: // Ctrl-C
				fmt.Fprint(promptW(cl), "\r\n")
				cl.interrupted = true
				return "", interruptedErr()
			case c == '\r' || c == '\n' || c == 4 && len(line) == 0:
				fmt.Fprint(promptW(cl), "\r\n")
				return string(line), nil
			case c == 0x7f || c == 8:
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
				b = b[1:]
			case c == 0x15: // Ctrl-U
				line, b = nil, b[1:]
			case c == 0x1b: // an escape sequence (arrows, bracketed paste marks): skipped
				i := 1
				if len(b) > 1 && (b[1] == '[' || b[1] == 'O') {
					i = 2
					for i < len(b) && (b[i] < 0x40 || b[i] > 0x7e) {
						i++
					}
					i++
				}
				b = b[min(i, len(b)):]
			case c < 0x20:
				b = b[1:]
			default:
				r, size := utf8.DecodeRune(b)
				line, b = append(line, r), b[size:]
			}
		}
		draw()
	}
}

// maskedRedraw is shown written over a line that held drawn characters,
// for a console that reads no escape sequences: spaces over what is left
// of the old line, then backspaces to the end of the new one.
func maskedRedraw(shown string, drawn int) string {
	n := drawn - utf8.RuneCountInString(shown)
	if n <= 0 {
		return shown
	}
	return shown + strings.Repeat(" ", n) + strings.Repeat("\b", n)
}
