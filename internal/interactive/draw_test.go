package interactive

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/out"
)

var update = flag.Bool("update", false, "rewrite testdata/draw/*.golden from the code as it is now")

// drawStates are the list states the golden screens show.
func drawStates() map[string]*List {
	start := NewList("Which host?", "", hosts(12), false)

	search := NewList("Which host?", "", hosts(12), false)
	typed(search, "web-1")

	nomatch := NewList("Which host?", "", hosts(12), false)
	typed(nomatch, "zz")

	free := NewList("Which hosts?", "", hosts(12), true)
	typed(free, "@web")

	empty := NewList("Which host?", "", nil, false)

	help := NewList("Which host?", "The host the command runs on. Type part of its name or address to narrow the list; Enter takes the highlighted row.", hosts(3), false)
	typed(help, "?")

	scrolled := NewList("Which host?", "", hosts(50), false)
	scrolled.Fit(14)
	key(scrolled, term.KeyEnd)

	long := NewList("Which database?", "", []Row{
		{Value: "a", Label: "orders-primary-eu-west-1-a-very-long-name", Detail: "postgres 16 on db-01.internal.example.com, the main store"},
		{Value: "b", Label: "x\x1b]0;owned\x07y", Detail: "a name with a control sequence"},
		{Value: "c", Label: "数据库", Detail: "wide characters"},
	}, false)
	key(long, term.KeyDown)

	return map[string]*List{"start": start, "search": search, "nomatch": nomatch, "free": free, "empty": empty, "help": help, "scrolled": scrolled, "long": long}
}

var drawStyles = map[string]Style{
	"w80-color": {Width: 80, Color: true},
	"w60-plain": {Width: 60},
}

func golden(t *testing.T, name string, lines []string) {
	t.Helper()
	got := strings.ReplaceAll(strings.Join(lines, "\n"), "\x1b", "^[") + "\n"
	p := filepath.Join("testdata", "draw", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/interactive -update to write it)", err)
	}
	if got != string(want) {
		t.Errorf("%s:\n--- want\n%s--- got\n%s", p, want, got)
	}
}

func unicodeMarks(t *testing.T, ok bool) {
	t.Helper()
	was := out.UnicodeOK
	out.UnicodeOK = func() bool { return ok }
	t.Cleanup(func() { out.UnicodeOK = was })
}

// Each state at width 80 with colour and at width 60 without.
func TestDrawGolden(t *testing.T) {
	unicodeMarks(t, true)
	for sn, l := range drawStates() {
		for yn, s := range drawStyles {
			golden(t, sn+"-"+yn, Draw(l, s))
		}
	}
}

// A terminal that cannot show the marks gets them in ASCII.
func TestDrawGoldenASCII(t *testing.T) {
	unicodeMarks(t, false)
	golden(t, "start-ascii", Draw(drawStates()["start"], Style{Width: 80}))
}

var escapes = regexp.MustCompile("\x1b\\[[0-9;]*m")

// No line is wider than the window or 80 columns, whichever is less, and
// without colour no line holds an escape sequence.
func TestDrawFitsWidth(t *testing.T) {
	unicodeMarks(t, true)
	for sn, l := range drawStates() {
		for w := 10; w <= 120; w++ {
			for _, color := range []bool{true, false} {
				for i, line := range Draw(l, Style{Width: w, Color: color}) {
					if !color && strings.Contains(line, "\x1b") {
						t.Fatalf("%s width %d line %d has an escape without colour: %q", sn, w, i, line)
					}
					if got := term.DisplayWidth(escapes.ReplaceAllString(line, "")); got > min(w, 80) {
						t.Fatalf("%s width %d line %d is %d wide: %q", sn, w, i, got, line)
					}
				}
			}
		}
	}
}

// formStates are the form states the golden screens show.
func formStates() map[string]*Form {
	title := "komando database postgres query"
	start := NewForm(title, testFields(), testLister)

	typedSQL := NewForm(title, testFields(), testLister)
	fkey(typedSQL, term.KeyEnter)
	ftyped(typedSQL, "select * from orders")

	needed := NewForm(title, testFields(), testLister)
	fkey(needed, term.KeyEnter)
	fkey(needed, term.KeyEnter)

	help := NewForm(title, testFields(), testLister)
	fkey(help, term.KeyEnter)
	ftyped(help, "?")

	more := NewForm(title, testFields(), testLister)
	fkey(more, term.KeyEnter)
	ftyped(more, "select 1")
	fkey(more, term.KeyEnter)

	def := NewForm(title, testFields(), testLister)
	fkey(def, term.KeyEnter)
	ftyped(def, "select 1")
	fkey(def, term.KeyEnter)
	fkey(def, term.KeyDown)
	fkey(def, term.KeyEnter)

	return map[string]*Form{"form-start": start, "form-typed": typedSQL, "form-needed": needed, "form-help": help, "form-more": more, "form-default": def}
}

// Each form state at width 80 with colour and at width 60 without.
func TestDrawFormGolden(t *testing.T) {
	unicodeMarks(t, true)
	for sn, f := range formStates() {
		for yn, s := range drawStyles {
			golden(t, sn+"-"+yn, DrawForm(f, s))
		}
	}
}

// A form's lines fit the window too, and start with the command's words.
func TestDrawFormFitsWidth(t *testing.T) {
	unicodeMarks(t, true)
	for sn, f := range formStates() {
		for w := 10; w <= 120; w++ {
			lines := DrawForm(f, Style{Width: w, Color: true})
			if !strings.HasPrefix(lines[0], "komando ") && w >= 20 {
				t.Fatalf("%s width %d: line 1 is %q, want the command's words", sn, w, lines[0])
			}
			for i, line := range lines {
				if got := term.DisplayWidth(escapes.ReplaceAllString(line, "")); got > min(w, 80) {
					t.Fatalf("%s width %d line %d is %d wide: %q", sn, w, i, got, line)
				}
			}
		}
	}
}

// A narrow window drops whole key hints, the least needed first; the key
// that stops is always there and no hint is cut in half.
func TestDrawKeyLineNarrow(t *testing.T) {
	unicodeMarks(t, true)
	l := drawStates()["start"]
	want := map[int]string{
		80: "Enter take · Esc back · type to search · ? help · Ctrl-C stop",
		60: "Enter take · Esc back · ? help · Ctrl-C stop",
		40: "Enter take · Esc back · Ctrl-C stop",
		30: "Enter take · Ctrl-C stop",
	}
	for w, k := range want {
		lines := Draw(l, Style{Width: w})
		if got := lines[len(lines)-1]; got != k {
			t.Errorf("width %d: key line %q, want %q", w, got, k)
		}
	}
}

// The order of a screen never changes, for a screen reader: the question
// first, then the help, then the rows, the key line last; the highlighted
// row is marked with > and not by colour alone.
func TestDrawOrder(t *testing.T) {
	unicodeMarks(t, true)
	l := drawStates()["help"]
	lines := Draw(l, Style{Width: 80})
	if !strings.HasPrefix(lines[0], "Which host?") {
		t.Errorf("line 1 is %q, want the question", lines[0])
	}
	if !strings.HasPrefix(lines[1], "  The host") {
		t.Errorf("line 2 is %q, want the help", lines[1])
	}
	if !strings.HasPrefix(lines[len(lines)-1], "Enter take") {
		t.Errorf("the last line is %q, want the key line", lines[len(lines)-1])
	}
	marked := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "> ") {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("%d rows start with >, want 1: %q", marked, lines)
	}
}
