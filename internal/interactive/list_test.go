package interactive

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

func hosts(n int) []Row {
	rows := make([]Row, n)
	for i := range rows {
		rows[i] = Row{Value: fmt.Sprintf("h%02d", i+1), Label: fmt.Sprintf("web-%02d", i+1), Detail: "10.0.0." + fmt.Sprint(i+1)}
	}
	return rows
}

func typed(l *List, s string) {
	for _, r := range s {
		l.Key(term.Key{Kind: term.KeyRune, Rune: r})
	}
}

func key(l *List, k term.KeyKind) (Result, string) { return l.Key(term.Key{Kind: k}) }

func values(rows []Row) string {
	var v []string
	for _, r := range rows {
		v = append(v, r.Value)
	}
	return strings.Join(v, ",")
}

// Typing narrows the list on name and detail, ignoring case, the same
// match as the line prompts' askPick.
func TestListSearchNarrows(t *testing.T) {
	l := NewList("Which host?", "", []Row{
		{Value: "a", Label: "web-1", Detail: "nginx"},
		{Value: "b", Label: "DB-1", Detail: "postgres"},
		{Value: "c", Label: "cache", Detail: "redis on web"},
	}, false)
	tests := []struct{ typed, want string }{
		{"", "a,b,c"},
		{"web", "a,c"},
		{"WEB", "a,c"},
		{"db", "b"},
		{"postgres", "b"},
		{"zz", ""},
	}
	for _, tt := range tests {
		key(l, term.KeyClear)
		typed(l, tt.typed)
		if got := values(l.Shown()); got != tt.want {
			t.Errorf("after %q the list shows %q, want %q", tt.typed, got, tt.want)
		}
	}
}

// Backspace removes one character of the search, Ctrl-U all of it.
func TestListSearchEdit(t *testing.T) {
	l := NewList("Which host?", "", hosts(12), false)
	typed(l, "web-11")
	if got := values(l.Shown()); got != "h11" {
		t.Fatalf("web-11 shows %q", got)
	}
	key(l, term.KeyBackspace)
	if got := values(l.Shown()); got != "h10,h11,h12" {
		t.Errorf("after Backspace the list shows %q, want h10,h11,h12", got)
	}
	key(l, term.KeyClear)
	if got := len(l.Shown()); got != 12 {
		t.Errorf("after Ctrl-U the list shows %d rows, want 12", got)
	}
	key(l, term.KeyBackspace) // nothing left to remove
	if got := len(l.Shown()); got != 12 {
		t.Errorf("Backspace on an empty search changed the list to %d rows", got)
	}
}

// Moving: Up and Down by one, Page Up and Down by a page, Home and End
// to the ends; never past them.
func TestListMoves(t *testing.T) {
	l := NewList("Which host?", "", hosts(50), false)
	l.Fit(14) // a window of 14 rows leaves a page of 9
	steps := []struct {
		k    term.KeyKind
		want string
	}{
		{term.KeyUp, "h01"},
		{term.KeyDown, "h02"},
		{term.KeyPageDown, "h11"},
		{term.KeyPageDown, "h20"},
		{term.KeyPageUp, "h11"},
		{term.KeyEnd, "h50"},
		{term.KeyDown, "h50"},
		{term.KeyPageDown, "h50"},
		{term.KeyHome, "h01"},
		{term.KeyPageUp, "h01"},
	}
	for i, s := range steps {
		key(l, s.k)
		if got := l.Current().Value; got != s.want {
			t.Fatalf("step %d (key %d): on %s, want %s", i, s.k, got, s.want)
		}
	}
}

// The highlighted row always stays on the page that is drawn.
func TestListScrollKeepsCurrentShown(t *testing.T) {
	l := NewList("Which host?", "", hosts(50), false)
	l.Fit(14)
	for i := 0; i < 49; i++ {
		key(l, term.KeyDown)
		if c, top := l.cur, l.top; c < top || c >= top+l.page {
			t.Fatalf("after %d Down: row %d is outside the page %d..%d", i+1, c, top, top+l.page-1)
		}
	}
	for i := 0; i < 49; i++ {
		key(l, term.KeyUp)
		if c, top := l.cur, l.top; c < top || c >= top+l.page {
			t.Fatalf("after %d Up: row %d is outside the page %d..%d", i+1, c, top, top+l.page-1)
		}
	}
}

// A new search starts again at the first row that matches.
func TestListSearchResetsPosition(t *testing.T) {
	l := NewList("Which host?", "", hosts(50), false)
	l.Fit(14)
	key(l, term.KeyEnd)
	typed(l, "web-1") // web-10 to web-19
	if got := l.Current().Value; got != "h10" {
		t.Errorf("after a search the highlight is on %s, want the first match h10", got)
	}
	if l.top != 0 {
		t.Errorf("after a search the page starts at %d, want 0", l.top)
	}
}

// Enter takes the highlighted row's value; with nothing shown it takes
// nothing, unless the list is free: then it takes the typed text.
func TestListEnter(t *testing.T) {
	l := NewList("Which host?", "", hosts(3), false)
	key(l, term.KeyDown)
	if r, v := key(l, term.KeyEnter); r != Take || v != "h02" {
		t.Errorf("Enter gave %v %q, want Take h02", r, v)
	}
	typed(l, "nothing")
	if r, v := key(l, term.KeyEnter); r != Stay || v != "" {
		t.Errorf("Enter with no match gave %v %q, want Stay", r, v)
	}
	free := NewList("Which hosts?", "", hosts(3), true)
	typed(free, "@web")
	if r, v := key(free, term.KeyEnter); r != Take || v != "@web" {
		t.Errorf("Enter in a free list gave %v %q, want Take @web", r, v)
	}
	empty := NewList("Which hosts?", "", hosts(3), true)
	key(empty, term.KeyClear)
	typed(empty, "zz")
	key(empty, term.KeyClear)
	if r, v := key(empty, term.KeyEnter); r != Take || v != "h01" {
		t.Errorf("Enter after clearing the search gave %v %q, want Take h01", r, v)
	}
}

// Esc clears the search first; on an empty search it goes back.
func TestListEsc(t *testing.T) {
	l := NewList("Which host?", "", hosts(3), false)
	typed(l, "web-2")
	if r, _ := key(l, term.KeyEsc); r != Stay || len(l.Shown()) != 3 {
		t.Errorf("Esc with a search gave %v and %d rows, want Stay and the search cleared", r, len(l.Shown()))
	}
	if r, _ := key(l, term.KeyEsc); r != Back {
		t.Errorf("Esc on an empty search gave %v, want Back", r)
	}
}

// Ctrl-C quits at once, whatever was typed.
func TestListInterrupt(t *testing.T) {
	l := NewList("Which host?", "", hosts(3), false)
	typed(l, "web")
	if r, v := key(l, term.KeyInterrupt); r != Quit || v != "" {
		t.Errorf("Ctrl-C gave %v %q, want Quit", r, v)
	}
}

// ? in an empty search shows the help and hides it again; anywhere else
// it is part of the search.
func TestListHelp(t *testing.T) {
	l := NewList("Which host?", "the host the command runs on", hosts(3), false)
	typed(l, "?")
	if !l.help || l.search != "" {
		t.Fatalf("? on an empty search: help %v, search %q", l.help, l.search)
	}
	typed(l, "?")
	if l.help {
		t.Error("a second ? did not hide the help")
	}
	typed(l, "w?")
	if l.help || l.search != "w?" {
		t.Errorf("? after text: help %v, search %q, want the ? searched", l.help, l.search)
	}
}

// A paste goes into the search as one line, without control characters.
func TestListPaste(t *testing.T) {
	l := NewList("Which hosts?", "", hosts(3), true)
	l.Key(term.Key{Kind: term.KeyPaste, Text: "tag:\tprod\n"})
	if l.search != "tag:prod" {
		t.Errorf("the paste made the search %q, want %q", l.search, "tag:prod")
	}
}

// Keys that mean nothing in a list change nothing.
func TestListIgnoredKeys(t *testing.T) {
	l := NewList("Which host?", "", hosts(3), false)
	key(l, term.KeyDown)
	for _, k := range []term.KeyKind{term.KeyNone, term.KeyLeft, term.KeyRight, term.KeyTab, term.KeyBackTab, term.KeyDelete, term.KeyEOF, term.KeyResize, term.KeySuspend} {
		if r, v := key(l, k); r != Stay || v != "" {
			t.Errorf("key %d gave %v %q, want Stay", k, r, v)
		}
	}
	if got := l.Current().Value; got != "h02" {
		t.Errorf("ignored keys moved the highlight to %s", got)
	}
}

// An empty list has no current row and Enter takes nothing.
func TestListEmpty(t *testing.T) {
	l := NewList("Which host?", "", nil, false)
	if (l.Current() != Row{}) {
		t.Errorf("an empty list has current row %+v", l.Current())
	}
	for _, k := range []term.KeyKind{term.KeyDown, term.KeyUp, term.KeyEnd, term.KeyPageDown, term.KeyEnter} {
		if r, _ := key(l, k); r != Stay {
			t.Errorf("key %d on an empty list gave %v, want Stay", k, r)
		}
	}
}
