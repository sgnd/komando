package interactive

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

func testFields() []Field {
	return []Field{
		{Key: "arg0", Ask: "Which database?", Rows: rows(dbRows...), Required: true},
		{Key: "arg1", Ask: "Which SQL?", Help: "one statement", Required: true},
		{Key: "flag:limit", Ask: "How many rows at most?", Default: fixed("100"), Advanced: true},
		{Key: "flag:format", Ask: "Which format?", Rows: rows(Row{Value: "table", Label: "table"}, Row{Value: "csv", Label: "csv"}), Advanced: true},
	}
}

var dbRows = []Row{{Value: "orders", Label: "orders"}, {Value: "users", Label: "users"}}

func rows(r ...Row) func(Answers) []Row { return func(Answers) []Row { return r } }

func fixed(v string) func(Answers) string { return func(Answers) string { return v } }

func fkey(f *Form, k term.KeyKind) (Result, map[string]string) { return f.Key(term.Key{Kind: k}) }

func ftyped(f *Form, s string) {
	for _, r := range s {
		f.Key(term.Key{Kind: term.KeyRune, Rune: r})
	}
}

// The required fields come first, in order; Enter takes each answer and
// moves on; after them the form asks whether to see more options.
func TestFormFillsInOrder(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	if got := f.Field().Key; got != "arg0" {
		t.Fatalf("first field %s, want arg0", got)
	}
	fkey(f, term.KeyDown) // users
	fkey(f, term.KeyEnter)
	ftyped(f, "select 1")
	fkey(f, term.KeyEnter)
	if !f.AtMore() {
		t.Fatalf("after the required fields the form is on %q, want the more-options step", f.Field().Key)
	}
	r, a := fkey(f, term.KeyEnter) // the first row: review now
	if r != Take {
		t.Fatalf("Enter on review now gave %v", r)
	}
	want := map[string]string{"arg0": "users", "arg1": "select 1"}
	if !maps.Equal(a, want) {
		t.Errorf("answers %v, want %v", a, want)
	}
}

// More options adds the advanced fields; a default stands when Enter is
// pressed on an empty field, and choices are picked from a list.
func TestFormMoreOptions(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	fkey(f, term.KeyEnter)
	ftyped(f, "select 1")
	fkey(f, term.KeyEnter)
	fkey(f, term.KeyDown) // more options
	fkey(f, term.KeyEnter)
	if got := f.Field().Key; got != "flag:limit" {
		t.Fatalf("after more options the field is %s, want flag:limit", got)
	}
	fkey(f, term.KeyEnter) // the default
	fkey(f, term.KeyDown)  // csv
	r, a := fkey(f, term.KeyEnter)
	if r != Take {
		t.Fatalf("Enter on the last field gave %v, want Take", r)
	}
	want := map[string]string{"arg0": "orders", "arg1": "select 1", "flag:limit": "100", "flag:format": "csv"}
	if !maps.Equal(a, want) {
		t.Errorf("answers %v, want %v", a, want)
	}
}

// A required field takes no empty answer: the form says why and stays.
func TestFormRequired(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	fkey(f, term.KeyEnter)
	if r, _ := fkey(f, term.KeyEnter); r != Stay || f.Field().Key != "arg1" {
		t.Fatalf("empty Enter on a required field gave %v on %s", r, f.Field().Key)
	}
	if f.problem == "" {
		t.Error("no reason given for the empty required answer")
	}
	ftyped(f, "x")
	if f.problem != "" {
		t.Errorf("the reason %q stays after typing", f.problem)
	}
}

// Tab and Shift-Tab move between fields and keep what was typed.
func TestFormTab(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	fkey(f, term.KeyTab)
	ftyped(f, "select 2")
	fkey(f, term.KeyBackTab)
	if got := f.Field().Key; got != "arg0" {
		t.Fatalf("Shift-Tab went to %s, want arg0", got)
	}
	fkey(f, term.KeyTab)
	if got := f.Text(); got != "select 2" {
		t.Errorf("back on arg1 the text is %q, want select 2", got)
	}
	fkey(f, term.KeyBackTab)
	fkey(f, term.KeyBackTab) // nothing before the first field
	if got := f.Field().Key; got != "arg0" {
		t.Errorf("Shift-Tab past the first field went to %s", got)
	}
}

// A free pick takes typed text that matches no row (a selector).
func TestFormFreePick(t *testing.T) {
	f := NewForm("komando host exec", []Field{{Key: "arg0", Ask: "Which hosts?", Rows: rows(dbRows...), Free: true, Required: true}})
	ftyped(f, "tag:prod")
	r, a := fkey(f, term.KeyEnter)
	if r != Take || a["arg0"] != "tag:prod" {
		t.Errorf("a free pick gave %v %v, want Take tag:prod", r, a)
	}
}

// Esc clears what is typed first; on an empty field it is Back (to the
// menu); Ctrl-C quits at once.
func TestFormEscAndInterrupt(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	fkey(f, term.KeyEnter)
	ftyped(f, "select 1")
	if r, _ := fkey(f, term.KeyEsc); r != Stay || f.Text() != "" {
		t.Fatalf("Esc with text gave %v and %q", r, f.Text())
	}
	if r, _ := fkey(f, term.KeyEsc); r != Back {
		t.Errorf("Esc on an empty field gave %v, want Back", r)
	}
	if r, _ := fkey(f, term.KeyInterrupt); r != Quit {
		t.Errorf("Ctrl-C gave %v, want Quit", r)
	}
}

// Text editing: Backspace, Ctrl-U, a paste on one line; ? on an empty
// field shows its help.
func TestFormTextEditing(t *testing.T) {
	f := NewForm("komando database postgres query", testFields())
	fkey(f, term.KeyTab)
	ftyped(f, "?")
	if !f.help || f.Text() != "" {
		t.Fatalf("? on an empty field: help %v, text %q", f.help, f.Text())
	}
	f.Key(term.Key{Kind: term.KeyPaste, Text: "select\n1\tx\x1b"})
	if got := f.Text(); got != "select 1 x" {
		t.Errorf("after the paste the text is %q, want lines and tabs as spaces, no control characters", got)
	}
	fkey(f, term.KeyBackspace)
	if got := f.Text(); got != "select 1 " {
		t.Errorf("after Backspace the text is %q", got)
	}
	fkey(f, term.KeyClear)
	if got := f.Text(); got != "" {
		t.Errorf("Ctrl-U left %q", got)
	}
}

// The answers hold only fields that were given a value.
func TestFormAnswersSkipEmpty(t *testing.T) {
	f := NewForm("komando x", []Field{{Key: "arg0", Ask: "Name?"}, {Key: "flag:note", Ask: "Note?"}})
	ftyped(f, "a")
	fkey(f, term.KeyEnter)
	_, a := fkey(f, term.KeyEnter)
	if keys := slices.Sorted(maps.Keys(a)); strings.Join(keys, ",") != "arg0" {
		t.Errorf("answers %v, want arg0 only", a)
	}
}

// A field whose Show says false is skipped, both ways, and its answer is
// left out; Default and Rows follow the answers given so far.
func TestFormFollowsAnswers(t *testing.T) {
	fields := []Field{
		{Key: "arg0", Ask: "Which kind?", Rows: rows(Row{Value: "postgres", Label: "postgres"}, Row{Value: "mysql", Label: "mysql"}), Required: true},
		{Key: "flag:schema", Ask: "Which schema?", Show: func(a Answers) bool { return a["arg0"] == "postgres" }},
		{Key: "flag:port", Ask: "Which port?", Default: func(a Answers) string {
			if a["arg0"] == "mysql" {
				return "3306"
			}
			return "5432"
		}},
		{Key: "flag:db", Ask: "Which database?", Rows: func(a Answers) []Row {
			return []Row{{Value: a["arg0"] + "-main", Label: a["arg0"] + "-main"}}
		}},
	}
	f := NewForm("komando x", fields)
	fkey(f, term.KeyDown) // mysql
	fkey(f, term.KeyEnter)
	if got := f.Field().Key; got != "flag:port" {
		t.Fatalf("after mysql the field is %s, want flag:port (schema is for postgres only)", got)
	}
	fkey(f, term.KeyEnter) // the default
	if got := f.Text(); got != "" {
		t.Fatalf("on the database field the text is %q", got)
	}
	r, a := fkey(f, term.KeyEnter)
	if r != Take {
		t.Fatalf("the last Enter gave %v", r)
	}
	want := map[string]string{"arg0": "mysql", "flag:port": "3306", "flag:db": "mysql-main"}
	if !maps.Equal(a, want) {
		t.Errorf("answers %v, want %v", a, want)
	}

	g := NewForm("komando x", fields)
	fkey(g, term.KeyEnter) // postgres
	ftyped(g, "public")
	fkey(g, term.KeyEnter)
	fkey(g, term.KeyBackTab)
	fkey(g, term.KeyBackTab)
	fkey(g, term.KeyDown) // mysql now
	fkey(g, term.KeyEnter)
	fkey(g, term.KeyEnter)
	_, a = fkey(g, term.KeyEnter)
	if _, ok := a["flag:schema"]; ok {
		t.Errorf("a hidden field's answer was kept: %v", a)
	}
	if a["flag:db"] != "mysql-main" {
		t.Errorf("the database list did not follow the new kind: %v", a)
	}
}

// Check refuses an answer with its reason, and the form stays on the
// field until the answer passes.
func TestFormCheck(t *testing.T) {
	f := NewForm("komando x", []Field{{Key: "flag:port", Ask: "Which port?", Check: func(_ Answers, v string) string {
		if strings.Trim(v, "0123456789") != "" {
			return "a port is a number"
		}
		return ""
	}}})
	ftyped(f, "http")
	if r, _ := fkey(f, term.KeyEnter); r != Stay || f.problem != "a port is a number" {
		t.Fatalf("a wrong port gave %v and %q", r, f.problem)
	}
	fkey(f, term.KeyClear)
	ftyped(f, "8080")
	if r, a := fkey(f, term.KeyEnter); r != Take || a["flag:port"] != "8080" {
		t.Errorf("a right port gave %v %v", r, a)
	}
}

// Clean keeps a pasted password out of the screen while it is typed, and
// takes it out of the answer on Enter, saying so.
func TestFormClean(t *testing.T) {
	clean := func(s string) (string, bool) {
		if i, j := strings.Index(s, ":"), strings.LastIndex(s, "@"); i >= 0 && j > i {
			return s[:i] + s[j:], true
		}
		return s, false
	}
	f := NewForm("komando x", []Field{{Key: "arg0", Ask: "Which address?", Clean: clean}, {Key: "arg1", Ask: "Name?"}})
	f.Key(term.Key{Kind: term.KeyPaste, Text: "root:hunter2@db.example.com"})
	for _, l := range DrawForm(f, Style{Width: 80}) {
		if strings.Contains(l, "hunter2") {
			t.Fatalf("the password is drawn: %q", l)
		}
	}
	fkey(f, term.KeyEnter)
	if got := f.text["arg0"]; got != "root@db.example.com" {
		t.Errorf("the answer is %q, want the password taken out", got)
	}
	if !strings.Contains(f.notice, "password") {
		t.Errorf("no notice that a password was taken out: %q", f.notice)
	}
}
