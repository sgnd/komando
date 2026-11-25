package interactive

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/out"
)

// Style is how a screen is drawn: the window's width, and whether the
// highlighted row is also shown in reverse video (never by colour alone:
// it starts with > either way).
type Style struct {
	Width int
	Color bool
}

// maxWidth is the widest a screen draws, whatever the window (M-9).
const maxWidth = 80

const reverse, reset = "\x1b[7m", "\x1b[0m"

// Draw is the list as lines, top to bottom, in an order that never
// changes: the question with what was typed, the help when asked for, the
// rows of the page, a line under them when there is something to say, and
// the key line. It only reads l.
func Draw(l *List, s Style) []string {
	w := min(s.Width, maxWidth)
	q := l.Question
	if l.search != "" {
		q += " " + l.search
	}
	lines := []string{term.TruncateWidth(q, w)}
	if l.help {
		help := l.Help
		if help == "" {
			help = "no help for this question"
		}
		for _, h := range wrap(help, w-2) {
			lines = append(lines, "  "+h)
		}
	}
	shown := l.Shown()
	page := shown[min(l.top, len(shown)):min(l.top+l.page, len(shown))]
	labelW := 0
	for _, r := range shown {
		labelW = max(labelW, term.DisplayWidth(term.CleanText(r.Label)))
	}
	labelW = min(labelW, max(1, (w-4)/2))
	for i, r := range page {
		mark := "  "
		if l.top+i == l.cur {
			mark = "> "
		}
		label := term.TruncateWidth(term.CleanText(r.Label), labelW)
		line := mark + label
		if d := term.CleanText(r.Detail); d != "" {
			line += strings.Repeat(" ", labelW-term.DisplayWidth(label)+2) + d
		}
		line = term.TruncateWidth(line, w)
		if mark == "> " && s.Color {
			line = reverse + line + reset
		}
		lines = append(lines, line)
	}
	if under := l.under(len(shown)); under != "" {
		lines = append(lines, term.TruncateWidth(under, w))
	}
	esc := "Esc back"
	if l.search != "" {
		esc = "Esc clear"
	}
	return append(lines, keyLine(w, "Enter take", esc, "type to search", "? help", "Ctrl-C stop"))
}

// keyLine joins the key hints with " · " in at most w columns. A narrow
// window drops whole hints, the least needed first: the third to the one
// before the last, in order, then the second. The first and the last
// (stop) stay.
func keyLine(w int, hints ...string) string {
	var drop []int
	for i := 2; i < len(hints)-1; i++ {
		drop = append(drop, i)
	}
	if len(hints) > 2 {
		drop = append(drop, 1)
	}
	keep := make([]bool, len(hints))
	for i := range keep {
		keep[i] = true
	}
	for {
		var shown []string
		for i, h := range hints {
			if keep[i] {
				shown = append(shown, h)
			}
		}
		line := out.Marks(strings.Join(shown, " · "))
		if term.DisplayWidth(line) <= w || len(drop) == 0 {
			return term.TruncateWidth(line, w)
		}
		keep[drop[0]], drop = false, drop[1:]
	}
}

// DrawForm is the form as lines: the command's words, then the field
// being filled (a list as Draw shows it, or the question with what is
// typed), then its key line. It only reads f.
func DrawForm(f *Form, s Style) []string {
	w := min(s.Width, maxWidth)
	lines := []string{term.TruncateWidth(term.CleanText(f.Title), w)}
	if f.more != nil {
		return append(lines, Draw(f.more, s)...)
	}
	if l := f.list(); l != nil {
		return append(lines, Draw(l, s)...)
	}
	x, t := f.Field(), f.Text()
	def := ""
	if x.Default != nil {
		def = x.Default(f.answers(f.cur))
	}
	q := x.Ask + " " + t
	switch {
	case t == "" && def != "":
		q = x.Ask + " [" + def + "]"
	case t == "":
		q = x.Ask
	}
	lines = append(lines, term.TruncateWidth(q, w))
	if f.help {
		help := x.Help
		if help == "" {
			help = "no help for this question"
		}
		for _, h := range wrap(help, w-2) {
			lines = append(lines, "  "+h)
		}
	}
	if f.problem != "" {
		lines = append(lines, term.TruncateWidth("  ! "+f.problem, w))
	}
	esc := "Esc back"
	if t != "" {
		esc = "Esc clear"
	}
	return append(lines, keyLine(w, "Enter next", esc, "Tab skip", "? help", "Ctrl-C stop"))
}

// DrawReview is the review as lines: the question, the whole line with a
// $ first, then its keys. A line wider than the window wraps; no part of
// it is cut, so what runs is what was shown.
func DrawReview(r *Review, s Style) []string {
	w := min(s.Width, maxWidth)
	lines := []string{"Run this?"}
	for i, part := range hardWrap("komando "+r.line, max(1, w-4)) {
		prefix := "    "
		if i == 0 {
			prefix = "  $ "
		}
		lines = append(lines, prefix+part)
	}
	return append(lines, keyLine(w, "Enter run", "Esc back to the form", "Ctrl-C stop"))
}

// hardWrap breaks s into parts of at most w columns, keeping every
// character.
func hardWrap(s string, w int) []string {
	var parts []string
	part, used := []rune{}, 0
	for _, r := range s {
		rw := term.DisplayWidth(string(r))
		if used+rw > w && len(part) > 0 {
			parts = append(parts, string(part))
			part, used = nil, 0
		}
		part, used = append(part, r), used+rw
	}
	return append(parts, string(part))
}

// under is the line below the rows: why there are none, or how many more
// there are; "" when there is nothing to say.
func (l *List) under(n int) string {
	switch {
	case n == 0 && l.search != "" && l.Free:
		return "  Enter takes " + l.search + " as typed"
	case n == 0 && l.search != "":
		return "  nothing matches " + l.search
	case n == 0:
		return "  nothing to pick"
	case n > l.page:
		return fmt.Sprintf("  ... %d more: type part of a name to narrow the list", n-l.page)
	}
	return ""
}

// wrap breaks s into lines of at most w columns, at spaces; a word wider
// than w is cut.
func wrap(s string, w int) []string {
	w = max(w, 1)
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case term.DisplayWidth(line)+1+term.DisplayWidth(word) <= w:
			line += " " + word
		default:
			lines = append(lines, term.TruncateWidth(line, w))
			line = word
		}
	}
	return append(lines, term.TruncateWidth(line, w))
}
