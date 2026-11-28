package interactive

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

// Enter runs the line shown, Esc goes back to the form, Ctrl-C quits;
// every other key changes nothing.
func TestReviewKeys(t *testing.T) {
	r := NewReview("database postgres query orders 'select 1'")
	for _, k := range []term.KeyKind{term.KeyRune, term.KeyUp, term.KeyTab, term.KeyBackspace, term.KeyPaste} {
		if got := r.Key(term.Key{Kind: k, Rune: 'x'}); got != Stay {
			t.Errorf("key %d gave %v, want Stay", k, got)
		}
	}
	tests := map[term.KeyKind]Result{term.KeyEnter: Take, term.KeyEsc: Back, term.KeyInterrupt: Quit}
	for k, want := range tests {
		if got := r.Key(term.Key{Kind: k}); got != want {
			t.Errorf("key %d gave %v, want %v", k, got, want)
		}
	}
}

// The screen: the question, the line with a $ first, then the keys.
func TestDrawReview(t *testing.T) {
	unicodeMarks(t, true)
	lines := DrawReview(NewReview("host ssh exec web-1 -- uptime"), Style{Width: 80})
	want := []string{
		"Run this?",
		"  $ komando host ssh exec web-1 -- uptime",
		"Enter run · Esc back to the form · Ctrl-C stop",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("review screen:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// A line wider than the window wraps; not one character of it is cut,
// so what runs is what was shown.
func TestDrawReviewWrapsWholeLine(t *testing.T) {
	unicodeMarks(t, true)
	line := "host exec web-1 -- " + strings.Repeat("a-long-command-数据-", 8)
	for w := 10; w <= 90; w++ {
		lines := DrawReview(NewReview(line), Style{Width: w})
		var shown strings.Builder
		for _, l := range lines[1 : len(lines)-1] {
			if term.DisplayWidth(l) > min(w, 80) {
				t.Fatalf("width %d: line %q is too wide", w, l)
			}
			shown.WriteString(strings.TrimPrefix(strings.TrimPrefix(l, "  $ "), "    "))
		}
		if got := shown.String(); got != "komando "+line {
			t.Fatalf("width %d: the lines show %q, want the whole line %q", w, got, "komando "+line)
		}
	}
}
