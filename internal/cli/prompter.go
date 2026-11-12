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

	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
)

// A person at a terminal who leaves out what a command needs is asked for
// it, one line at a time, in the normal screen (the scrollback keeps it):
// `CONN (database):` with a numbered list of the databases komando knows,
// `--old:` for a flag. Nobody else is ever asked: an AI agent, a script, a
// pipe, CI, TERM=dumb and JSON output get the usage error they always got
// (docs/design/ux.md, section 10).

// promptable says whether komando may ask: stdin, stdout and stderr are
// terminals, no AI agent runs it, it is not CI, the terminal is not dumb
// and the output is text (format is what -o or KOMANDO_OUTPUT asked for).
// Every question checks it; no command looks at the terminal on its own.
var promptable = func(format string) bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) &&
		term.IsTerminal(int(os.Stderr.Fd())) && promptGate(format, isAgent(), os.Getenv("CI"), os.Getenv("TERM"))
}

// promptGate is promptable without the terminal checks, so tests can try
// each condition.
func promptGate(format string, agent bool, ci, termName string) bool {
	ciOn := ci != "" && ci != "false" && ci != "0"
	return !agent && !ciOn && termName != "dumb" && (format == "" || format == "auto" || format == "text")
}

// promptOn is set once promptable said yes for this command; a question
// asked without it is a bug (a test fails on it at once).
var promptOn bool

// promptW is where questions are drawn; promptRead reads one answer. Tests
// stand in for both.
var (
	promptW    io.Writer = os.Stderr
	promptRead           = func(label string) (string, error) { return promptLineIdle(label, promptIdle) }
)

// promptIdle: a question nobody answers for this long is given up, so a
// program that looks like a person cannot hang on it forever.
const promptIdle = 10 * time.Minute

// errPromptCancel: the person stopped at a question (Ctrl-C, an empty
// answer where one was needed three times, no answer for promptIdle).
var errPromptCancel = errors.New("cancelled at a question")

// promptLineIdle reads one line from the terminal, or gives up after idle.
func promptLineIdle(label string, idle time.Duration) (string, error) {
	type answer struct {
		s   string
		err error
	}
	got := make(chan answer, 1)
	go func() { s, err := readAnswer(label, false); got <- answer{s, err} }()
	select {
	case a := <-got:
		return a.s, a.err
	case <-time.After(idle):
		fmt.Fprintln(promptW)
		return "", errPromptCancel
	}
}

func promptLine(label string) (string, error) {
	if !promptOn {
		if testing.Testing() {
			panic("a question was asked without a person at a terminal")
		}
		return "", out.Usage("komando cannot ask here: give every argument on the command line")
	}
	s, err := promptRead(label)
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
func promptHelp(q promptQ) {
	if q.help == "" {
		fmt.Fprintln(promptW, "  (no more help: type the value, or press Ctrl-C to stop)")
		return
	}
	for _, l := range menuWrap(q.help, 76) {
		fmt.Fprintln(promptW, "  "+l)
	}
}

// promptTries is how many wrong answers a question takes before it stops.
const promptTries = 3

// askText asks for a typed value: Enter takes the default, ? shows the
// help, a wrong answer says why and asks again.
func askText(q promptQ) (string, error) {
	label := q.label
	if q.def != "" {
		label += " [" + q.def + "]"
	}
	for try := 0; try < promptTries; {
		v, err := promptLine(label + ": ")
		if err != nil {
			return "", err
		}
		if v == "?" {
			promptHelp(q)
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
		fmt.Fprintln(promptW, "  ! "+problem)
		try++
	}
	return "", errPromptCancel
}

// askPick asks for one of rows by its number, or its value typed; other
// text narrows the list (free: it is taken as typed, as a selector like
// @web or tag:db, or a new name, is). Enter takes the default.
func askPick(q promptQ, rows []menuRow, free bool) (string, error) {
	shown := rows
	promptRows(shown)
	for try := 0; try < promptTries; {
		label := q.label
		if q.def != "" {
			label += " [" + q.def + "]"
		}
		v, err := promptLine(label + ": ")
		if err != nil {
			return "", err
		}
		switch {
		case v == "?":
			promptHelp(q)
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
						fmt.Fprintln(promptW, "  ! "+p)
						try++
						continue
					}
				}
				return v, nil
			}
			var match []menuRow
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
				promptRows(shown)
				continue
			}
		}
		fmt.Fprintln(promptW, "  ! type a number from the list (? explains it, Ctrl-C stops)")
		try++
	}
	return "", errPromptCancel
}

// promptMaxRows is how many rows a list shows at once; typing narrows it.
const promptMaxRows = 30

// promptRows prints a numbered list, its names and details in columns.
func promptRows(rows []menuRow) {
	w := 0
	for _, r := range rows[:min(len(rows), promptMaxRows)] {
		w = max(w, displayWidth(r.label))
	}
	for i, r := range rows[:min(len(rows), promptMaxRows)] {
		line := fmt.Sprintf("  %2d  %s", i+1, cleanText(r.label))
		if r.detail != "" {
			line += strings.Repeat(" ", w-displayWidth(r.label)+2) + cleanText(r.detail)
		}
		fmt.Fprintln(promptW, line)
	}
	if len(rows) > promptMaxRows {
		fmt.Fprintf(promptW, "  ... %d more: type part of a name to narrow the list\n", len(rows)-promptMaxRows)
	}
}

// askRun asks whether a command that komando filled in runs: y runs it,
// d runs it with --dry-run first (and asks again), anything else is no.
func askRun() (string, error) {
	v, err := promptLine("Run it? [y/N, d = --dry-run first]: ")
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

// askTypeName asks the person to type name to go on with something that
// cannot be undone; a wrong name is a no.
func askTypeName(name string) (bool, error) {
	v, err := promptLine("This cannot be undone. Type " + name + " to confirm: ")
	if err != nil {
		return false, err
	}
	return v == name, nil
}
