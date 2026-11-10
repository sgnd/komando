package cli

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// menuRow is one line a person can choose.
type menuRow struct {
	label, detail string
	value         string // what choosing it gives back (an action or a name)
}

// menuList is one screen of the menu: rows, where the cursor is, and (when
// typing is on) the filter typed so far. It knows nothing about terminals:
// update takes keys and render returns lines, so both are plain to test.
type menuList struct {
	title string  // the question above the rows ("" on the main menu)
	lead  [][]seg // lines under the title: a form's answers so far and its question
	note  string  // one dim line above the rows, when there is something to say
	warn  bool    // the note is a problem to fix, not a hint: marked "! " and shown bold
	// mask is how the typed line is drawn, when it must not show as typed
	// (a password pasted with an address); nil draws it as it is
	mask   func(string) string
	rows   []menuRow
	typing bool   // letters filter the rows instead of being shortcuts
	prompt string // what the typed line is for, instead of "Filter: " (Add)
	empty  string // said when no row is left to choose
	filter string
	cursor int // index into shown()
	top    int // first shown row on the screen

	hot     map[rune]string // keys that choose a value with no row (? for Help)
	hotPick string          // the value the last hot key chose
}

// menuOutcome is what a key did to the list.
type menuOutcome int

const (
	menuStay   menuOutcome = iota
	menuChosen             // Enter (or a number) on a row: see chosen()
	menuBack               // Esc, or Left on a list with one before it
	menuQuit               // q, Ctrl-C or Ctrl-D: leave the menu
)

// shown is the indexes of the rows the filter leaves, in order.
func (l *menuList) shown() []int {
	f := strings.ToLower(l.filter)
	var idx []int
	for i, r := range l.rows {
		if f == "" || strings.Contains(strings.ToLower(r.label+" "+r.detail), f) {
			idx = append(idx, i)
		}
	}
	return idx
}

// chosen is the row under the cursor, if any row is shown, or the value a
// hot key chose.
func (l *menuList) chosen() (menuRow, bool) {
	if l.hotPick != "" {
		return menuRow{value: l.hotPick}, true
	}
	s := l.shown()
	if len(s) == 0 {
		return menuRow{}, false
	}
	return l.rows[s[l.cursor]], true
}

// point puts the cursor on the row with this value, if there is one: the
// menu keeps the last choice by name, so a list that changed in between
// (a server added) still finds it.
func (l *menuList) point(value string) {
	if i := slices.IndexFunc(l.rows, func(r menuRow) bool { return r.value == value }); value != "" && i >= 0 && l.filter == "" {
		l.cursor = i
	}
}

// update applies one key. page is how many rows fit on the screen.
func (l *menuList) update(k menuKey, page int) menuOutcome {
	l.hotPick = ""
	n := len(l.shown())
	switch k.kind {
	case keyUp:
		l.cursor--
	case keyDown:
		l.cursor++
	case keyHome:
		l.cursor = 0
	case keyEnd:
		l.cursor = n - 1
	case keyPageUp:
		l.cursor -= page
	case keyPageDown:
		l.cursor += page
	case keyEnter, keyRight:
		if n > 0 {
			return menuChosen
		}
	case keyEsc:
		if l.filter == "" {
			return menuBack
		}
		l.setFilter("")
	case keyLeft:
		if l.title != "" { // on the main menu there is nothing to go back to: Esc or q quit
			return menuBack
		}
	case keyQuit:
		return menuQuit
	case keyBackspace:
		if _, size := utf8.DecodeLastRuneInString(l.filter); size > 0 {
			l.setFilter(l.filter[:len(l.filter)-size])
		}
	case keyClear:
		l.setFilter("")
	case keyRune:
		if l.typing {
			l.setFilter(l.filter + string(k.r))
		} else if o := l.shortcut(k.r, n); o != menuStay {
			return o
		}
	}
	l.clamp(page)
	return menuStay
}

// shortcut is a letter on a list without a filter: vim moves, q to quit,
// 1-9 to choose that row at once, and the list's hot keys.
func (l *menuList) shortcut(r rune, n int) menuOutcome {
	if v, ok := l.hot[r]; ok {
		l.hotPick = v
		return menuChosen
	}
	switch {
	case r == 'q' || r == 'Q':
		return menuQuit
	case r == 'k':
		l.cursor--
	case r == 'j':
		l.cursor++
	case r == 'g':
		l.cursor = 0
	case r == 'G':
		l.cursor = n - 1
	case r >= '1' && r <= '9' && int(r-'1') < n:
		l.cursor = int(r - '1')
		return menuChosen
	}
	return menuStay
}

func (l *menuList) setFilter(f string) {
	l.filter, l.cursor, l.top = f, 0, 0
}

// clamp keeps the cursor on a shown row and on the screen.
func (l *menuList) clamp(page int) {
	n := len(l.shown())
	l.cursor = max(0, min(l.cursor, n-1))
	page = max(1, page)
	if l.cursor < l.top {
		l.top = l.cursor
	}
	if l.cursor >= l.top+page {
		l.top = l.cursor - page + 1
	}
	l.top = max(0, min(l.top, n-page))
}

// menuScreen is everything around the list: the header and the key help.
type menuScreen struct {
	header []seg // first line: komando, its version, what it knows
	footer string
	color  bool
}

// listKeys is the key help of a list: how to move and choose, as this list
// takes them (numbers only on a list without a filter, and only as many as
// it has rows, up to 9), then the screen's own keys, like "Esc back".
func listKeys(l *menuList, more ...string) string {
	keys := []string{"↑↓ move", "Enter choose"}
	if n := min(9, len(l.rows)); !l.typing && n > 1 {
		keys[1] = fmt.Sprintf("Enter or 1-%d choose", n)
	}
	if l.typing {
		keys = append(keys, "type to filter")
	}
	return strings.Join(append(keys, more...), " · ")
}

// menuCaret is where the hidden cursor is left after drawing (line and
// column from 0; line -1: after the last line). Nothing shows there, but
// screen magnifiers and readers follow it to the chosen row.
type menuCaret struct{ line, col int }

// chrome is how many lines a screen uses besides the rows: blank, header,
// blank, then (title, filter, note, blank) when there is any of them, then
// after the rows blank and the key help, which takes more than one line on
// a narrow screen.
func (l *menuList) chrome(s menuScreen, width int) int {
	n := 4 + len(l.lead) + len(keyLines(s.footer, width-1))
	for _, on := range []bool{l.title != "", l.typing, l.note != ""} {
		if on {
			n++
		}
	}
	if l.title != "" || l.typing || l.note != "" {
		n++
	}
	return n
}

// pageSize is how many rows fit on a screen this wide and this many lines
// high.
func (l *menuList) pageSize(s menuScreen, width, height int) int {
	return max(1, height-l.chrome(s, width))
}

// keyLines is the key help cut into lines no wider than width, between its
// " · " parts, so a narrow screen shows every key in full instead of
// cutting off the last ones (often "q quit"). A part too wide on its own
// is cut by fit, as any line.
func keyLines(help string, width int) []string {
	if help == "" {
		return []string{""}
	}
	var lines []string
	for _, p := range strings.Split(help, " · ") {
		last := len(lines) - 1
		if last >= 0 && displayWidth(lines[last]+" · "+p) <= width {
			lines[last] += " · " + p
			continue
		}
		lines = append(lines, p)
	}
	return lines
}

// render draws the screen as lines no wider than width, at most height of
// them, so nothing wraps or scrolls and redrawing over them is exact. On a
// screen too short for everything, the blank lines go first, then the
// note, the header, the title and the key help's second line; the filter,
// the cursor row and the key help's first line stay. It also says where to
// leave the hidden cursor.
func (l *menuList) render(s menuScreen, width, height int) ([]string, menuCaret) {
	page := l.pageSize(s, width, height)
	l.clamp(page)
	shown := l.shown()
	type line struct {
		segs  []seg
		drop  int // the order lines go in on a short screen; 0 never
		caret int // column for the hidden cursor; -1 none
	}
	lines := []line{{nil, 1, -1}, {s.header, 6, -1}, {nil, 2, -1}}
	if l.title != "" {
		lines = append(lines, line{[]seg{{l.title, "1"}}, 7, -1})
	}
	for _, ld := range l.lead {
		lines = append(lines, line{ld, 5, -1})
	}
	if l.typing {
		label, text, count := l.typedLine(len(shown), width)
		lines = append(lines, line{[]seg{{label, "2"}, {text, ""}, {"_", "2"}, {count, "2"}}, 0, displayWidth(label + text)})
	}
	if l.note != "" {
		// a problem with the answer: it stays on any screen. The "! " says
		// so without colour, and bold reads on a light terminal as well as
		// a dark one, where yellow on white is hard to read.
		if l.warn {
			lines = append(lines, line{[]seg{{"! " + l.note, "1"}}, 0, -1})
		} else {
			lines = append(lines, line{[]seg{{l.note, "2"}}, 5, -1})
		}
	}
	if l.title != "" || l.typing || l.note != "" {
		lines = append(lines, line{nil, 3, -1})
	}
	rows, at := l.rowLines(shown, page)
	for i, r := range rows {
		lines = append(lines, line{r, 0, -1})
		if i == at {
			lines[len(lines)-1].caret = 0
			for j := range lines[:len(lines)-1] { // the row, not the filter
				lines[j].caret = -1
			}
		}
	}
	lines = append(lines, line{nil, 4, -1})
	for i, k := range keyLines(s.footer, width-1) {
		drop := 0
		if i > 0 {
			drop = 8
		}
		lines = append(lines, line{[]seg{{k, "2"}}, drop, -1})
	}
	for d := 1; len(lines) > max(0, height) && d <= 8; d++ {
		lines = slices.DeleteFunc(lines, func(x line) bool { return x.drop == d })
	}
	lines = lines[max(0, len(lines)-max(0, height)):] // still too many: keep the bottom
	text := make([]string, 0, len(lines))
	caret := menuCaret{-1, 0}
	for i, ln := range lines {
		text = append(text, fit(ln.segs, width-1, s.color))
		if ln.caret >= 0 {
			caret = menuCaret{i, min(ln.caret, max(0, width-1))}
		}
	}
	return text, caret
}

// typedLine is the line with what was typed: its label ("Filter: " or the
// prompt), the text, and how many rows are left. A text too long for the
// screen shows its end, after …, so the last key typed and the _ after it
// stay in sight; the count goes first, and on a very narrow screen the
// label too.
func (l *menuList) typedLine(shown, width int) (label, text, count string) {
	label, text, count = "Filter: ", l.filter, fmt.Sprintf("  %d of %d", shown, len(l.rows))
	if l.mask != nil {
		text = l.mask(text)
	}
	if l.prompt != "" {
		label, count = l.prompt, ""
	}
	room := width - 1 // what fit leaves, for label, text and _
	if displayWidth(label+text+count)+1 > room {
		count = ""
	}
	if displayWidth(label+text)+1 > room {
		if room-displayWidth(label) < 9 {
			label = ""
		}
		text = "…" + tailCols(text, room-displayWidth(label)-2)
	}
	return label, text, count
}

// tailCols is the end of s that fits in n terminal columns.
func tailCols(s string, n int) string {
	rs := []rune(s)
	i, w := len(rs), 0
	for i > 0 && w+runeWidth(rs[i-1]) <= n {
		w += runeWidth(rs[i-1])
		i--
	}
	return string(rs[i:])
}

// rowLines are the rows on the screen: the current one marked and in
// colour, numbers on a list without a filter, details lined up in one
// column for the whole list, so it does not move while a person types. at
// is the line of the cursor row, or -1.
func (l *menuList) rowLines(shown []int, page int) (lines [][]seg, at int) {
	if len(shown) == 0 {
		if l.filter != "" && len(l.rows) > 0 {
			return [][]seg{{{"  nothing matches; Esc clears the filter", "2"}}}, -1
		}
		return [][]seg{{{"  " + l.empty, "2"}}}, -1
	}
	w := 0
	for _, r := range l.rows {
		w = max(w, displayWidth(r.label))
	}
	w = min(w, 28)
	at = -1
	for i := l.top; i < min(len(shown), l.top+page); i++ {
		r := l.rows[shown[i]]
		mark, style := "  ", ""
		if i == l.cursor {
			mark, style, at = "> ", "36;1", len(lines)
		}
		label := r.label
		if !l.typing && i < 9 {
			label = fmt.Sprintf("%d. %s", i+1, label)
		}
		line := []seg{{mark + label, style}}
		if r.detail != "" {
			pad := strings.Repeat(" ", max(0, w-displayWidth(r.label)))
			line = []seg{{mark + label + pad, style}, {"  " + r.detail, "2"}}
		}
		lines = append(lines, line)
	}
	return lines, at
}

// seg is a piece of a line and its SGR style ("" for none).
type seg struct{ text, style string }

// fit joins the segments, cut to width terminal columns (a wide CJK
// character or emoji takes two), in colour when asked. A line that is cut
// ends in …, so a person can tell. It cuts the text before adding colour,
// so no escape code is ever cut.
func fit(line []seg, width int, color bool) string {
	total := 0
	for _, s := range line {
		total += displayWidth(s.text)
	}
	left, cut := max(0, width), total > width
	if cut {
		left = max(0, width-1) // room for …
	}
	var b strings.Builder
	for _, s := range line {
		var t strings.Builder
		full := true
		for _, r := range s.text {
			w := runeWidth(r)
			if w > left {
				full = false
				break
			}
			t.WriteRune(r)
			left -= w
		}
		if !full && width > 0 {
			t.WriteString("…")
		}
		text := t.String()
		if color && s.style != "" && text != "" {
			text = "\x1b[" + s.style + "m" + text + "\x1b[0m"
		}
		b.WriteString(text)
		if !full {
			break
		}
	}
	return b.String()
}
