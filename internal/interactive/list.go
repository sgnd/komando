// Package interactive is komando's interactive mode: the screens that
// help a person build a command line (C162). It returns the line as
// argv; internal/cli runs it as if it was typed, so every check of a typed
// line still applies. It reads keys and draws, nothing more: no command
// runs here (TestInteractiveImports).
package interactive

import (
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

// Row is one entry of a list: the value it stands for, the name shown and
// a detail beside it.
type Row struct {
	Value, Label, Detail string
}

// Result is what a key did to a screen.
type Result int

const (
	Stay Result = iota // nothing ends: draw again
	Take               // a value was taken
	Back               // Esc on an empty search: one level back
	Quit               // Ctrl-C: nothing runs
)

// MaxRows is how many rows a list shows at once, as the line prompts do
// (promptMaxRows); typing narrows it.
const MaxRows = 30

// reserved is the lines of a window a list does not use for rows: the
// question, the help, the line under the rows, the key line, and the line
// the person typed above the screen.
const reserved = 5

// List is a list with type-to-search. Free: when no row matches, Enter
// takes the typed text as it is (a selector such as @web or tag:prod).
type List struct {
	Question string
	Help     string
	Rows     []Row
	Free     bool

	search string
	help   bool // the help line is shown
	cur    int  // the highlighted row, in Shown
	top    int  // the first row of the page, in Shown
	page   int  // rows on a page
}

// NewList is a list of rows with nothing typed, the first row highlighted.
func NewList(question, help string, rows []Row, free bool) *List {
	return &List{Question: question, Help: help, Rows: rows, Free: free, page: MaxRows}
}

// Fit sets the page to a window of height rows: at most MaxRows, at
// least one.
func (l *List) Fit(height int) {
	l.page = max(1, min(MaxRows, height-reserved))
	l.scroll()
}

// Shown is the rows that match the search: on name and detail, ignoring
// case, the same match as the line prompts.
func (l *List) Shown() []Row {
	if l.search == "" {
		return l.Rows
	}
	want := strings.ToLower(l.search)
	var out []Row
	for _, r := range l.Rows {
		if strings.Contains(strings.ToLower(r.Label+" "+r.Detail), want) {
			out = append(out, r)
		}
	}
	return out
}

// Current is the highlighted row; the zero Row when nothing is shown.
func (l *List) Current() Row {
	if s := l.Shown(); l.cur < len(s) {
		return s[l.cur]
	}
	return Row{}
}

// Key applies one key. Take comes with the value taken.
func (l *List) Key(k term.Key) (Result, string) {
	n := len(l.Shown())
	switch k.Kind {
	case term.KeyRune:
		if k.Rune == '?' && l.search == "" {
			l.help = !l.help
			return Stay, ""
		}
		l.setSearch(l.search + string(k.Rune))
	case term.KeyPaste:
		l.setSearch(l.search + term.CleanText(k.Text))
	case term.KeyBackspace:
		if r := []rune(l.search); len(r) > 0 {
			l.setSearch(string(r[:len(r)-1]))
		}
	case term.KeyClear:
		l.setSearch("")
	case term.KeyUp:
		l.move(-1, n)
	case term.KeyDown:
		l.move(1, n)
	case term.KeyPageUp:
		l.move(-l.page, n)
	case term.KeyPageDown:
		l.move(l.page, n)
	case term.KeyHome:
		l.move(-n, n)
	case term.KeyEnd:
		l.move(n, n)
	case term.KeyEnter:
		switch {
		case n > 0:
			return Take, l.Current().Value
		case l.Free && l.search != "":
			return Take, l.search
		}
	case term.KeyEsc:
		if l.search == "" {
			return Back, ""
		}
		l.setSearch("")
	case term.KeyInterrupt:
		return Quit, ""
	}
	return Stay, ""
}

// setSearch narrows the list to s and starts again at its first row.
func (l *List) setSearch(s string) {
	l.search, l.cur, l.top = s, 0, 0
}

// move moves the highlight by d rows, never past either end.
func (l *List) move(d, n int) {
	if n == 0 {
		return
	}
	l.cur = max(0, min(n-1, l.cur+d))
	l.scroll()
}

// scroll keeps the highlighted row on the page.
func (l *List) scroll() {
	if l.cur < l.top {
		l.top = l.cur
	}
	if l.cur >= l.top+l.page {
		l.top = l.cur - l.page + 1
	}
}
