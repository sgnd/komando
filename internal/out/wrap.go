package out

import (
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// maxTextWidth is the widest line komando lays out for a person (M-9).
const maxTextWidth = 80

// StderrWidth is the width komando wraps its own stderr lines at (errors,
// hints, warnings): min(terminal width, 80) when stderr is a terminal, 0
// (no wrapping) when it is a pipe or a file, so an AI agent or a script
// reads each message on one line. Tests replace it.
var StderrWidth = func() int {
	fd := int(os.Stderr.Fd())
	if !term.IsTerminal(fd) {
		return 0
	}
	w, _, err := term.GetSize(fd)
	if err != nil || w <= 0 || w > maxTextWidth {
		return maxTextWidth
	}
	return w
}

// StdoutWidth is StderrWidth for stdout: the width a text result is laid
// out at for a person at a terminal, and 0 (no wrapping) when stdout is a
// pipe or a file, so `komando doctor -o text | grep` reads each line
// whole. Tests replace it.
var StdoutWidth = func() int {
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) {
		return 0
	}
	w, _, err := term.GetSize(fd)
	if err != nil || w <= 0 || w > maxTextWidth {
		return maxTextWidth
	}
	return w
}

// Wrap fills text into lines of at most width columns: the first line
// starts after a label of labelWidth columns, later lines with a hanging
// indent of two spaces. It breaks only at spaces, never inside a
// backticked command, so a command stays whole for copying; a word longer
// than the line (a URL, a path) gets a line of its own and is not cut.
// width 0 returns text unchanged. Text with its own line breaks keeps them.
func Wrap(text string, labelWidth, width int) string {
	if width <= 0 || !strings.Contains(text, " ") {
		return text
	}
	paras := strings.Split(text, "\n")
	for i, p := range paras {
		first := labelWidth
		if i > 0 {
			first = 0
		}
		paras[i] = wrapLine(p, first, width)
	}
	return strings.Join(paras, "\n")
}

func wrapLine(s string, used, width int) string {
	if used+utf8.RuneCountInString(s) <= width {
		return s
	}
	const indent = "  "
	var b strings.Builder
	col := used
	for i, w := range wrapWords(s) {
		n := utf8.RuneCountInString(w)
		if i > 0 {
			if col+1+n > width {
				b.WriteString("\n" + indent)
				col = len(indent)
			} else {
				b.WriteByte(' ')
				col++
			}
		}
		b.WriteString(w)
		col += n
	}
	return b.String()
}

// wrapWords splits s at the spaces outside backticks.
func wrapWords(s string) []string {
	var words []string
	var cur strings.Builder
	inTick := false
	for _, r := range s {
		switch {
		case r == '`':
			inTick = !inTick
			cur.WriteRune(r)
		case r == ' ' && !inTick:
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}
