package interactive

import (
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/cli/kit/term"
)

func leaf(state capability.State, short string, words ...string) capability.Leaf {
	k := capability.Key{Type: words[0]}
	switch len(words) {
	case 2:
		k.Verb = words[1]
	case 3:
		k.Provider, k.Verb = words[1], words[2]
	}
	return capability.Leaf{Key: k, Short: short, State: state}
}

func testLeaves() []capability.Leaf {
	return []capability.Leaf{
		leaf(capability.Built, "run a command on hosts", "host", "exec"),
		leaf(capability.Built, "list hosts", "host", "list"),
		leaf(capability.New, "not built yet", "host", "plan"),
		leaf(capability.Built, "run SQL", "database", "postgres", "query"),
		leaf(capability.Built, "list databases", "database", "postgres", "list"),
	}
}

func labels(l *List) string {
	var v []string
	for _, r := range l.Shown() {
		v = append(v, r.Label)
	}
	return strings.Join(v, ",")
}

// pick moves to the row labelled word and presses Enter.
func pick(t *testing.T, m *Menu, word string) (Result, capability.Leaf) {
	t.Helper()
	l := m.List()
	key(l, term.KeyHome)
	for i, r := range l.Shown() {
		if r.Label == word {
			for range i {
				m.Key(term.Key{Kind: term.KeyDown})
			}
			return m.Key(term.Key{Kind: term.KeyEnter})
		}
	}
	t.Fatalf("no row %q in %q", word, labels(l))
	return Stay, capability.Leaf{}
}

// The top level lists each first word once, in alphabetical order; each
// level below lists the next words; leaves in the plan only are left out.
func TestMenuLevels(t *testing.T) {
	m := NewMenu(testLeaves())
	if got := labels(m.List()); got != "database,host" {
		t.Fatalf("top level %q, want database,host", got)
	}
	if r, _ := pick(t, m, "host"); r != Stay {
		t.Fatalf("opening host gave %v", r)
	}
	if got := labels(m.List()); got != "exec,list" {
		t.Errorf("host level %q, want exec,list (plan is not built)", got)
	}
}

// Each row says what it is: a leaf its Short, a word the words below it.
func TestMenuDetails(t *testing.T) {
	m := NewMenu(testLeaves())
	if got := m.List().Shown()[0].Detail; got != "postgres" {
		t.Errorf("database's detail is %q, want postgres", got)
	}
	pick(t, m, "database")
	pick(t, m, "postgres")
	if got := m.List().Shown()[0]; got.Label != "list" || got.Detail != "list databases" {
		t.Errorf("first postgres row is %+v, want list with its Short", got)
	}
}

// Enter on a leaf takes it.
func TestMenuTakesLeaf(t *testing.T) {
	m := NewMenu(testLeaves())
	pick(t, m, "database")
	pick(t, m, "postgres")
	r, l := pick(t, m, "query")
	if r != Take || l.Key.String() != "database postgres query" {
		t.Errorf("Enter on query gave %v %q", r, l.Key.String())
	}
}

// A word that is a command and also has words after it (ssh-gate, and
// ssh-gate line) opens its level with the command itself as the first
// row.
func TestMenuCommandWithWordsAfter(t *testing.T) {
	m := NewMenu([]capability.Leaf{
		leaf(capability.Built, "the gate sshd runs", "gate"),
		leaf(capability.Built, "show the line", "gate", "line"),
	})
	if r, _ := pick(t, m, "gate"); r != Stay {
		t.Fatalf("opening gate gave %v", r)
	}
	if got := m.List().Shown()[0]; got.Label != "this command" || got.Detail != "the gate sshd runs" {
		t.Errorf("first row %+v, want this command with its Short", got)
	}
	if got := labels(m.List()); got != "this command,line" {
		t.Errorf("gate level %q", got)
	}
	if r, l := pick(t, m, "this command"); r != Take || l.Key.String() != "gate" {
		t.Errorf("this command gave %v %q, want Take gate", r, l.Key.String())
	}
	if r, l := pick(t, m, "line"); r != Take || l.Key.String() != "gate line" {
		t.Errorf("line gave %v %q, want Take gate line", r, l.Key.String())
	}
}

// Esc on an empty search goes up one level; at the top it is Back.
func TestMenuEscGoesUp(t *testing.T) {
	m := NewMenu(testLeaves())
	pick(t, m, "database")
	pick(t, m, "postgres")
	if r, _ := m.Key(term.Key{Kind: term.KeyEsc}); r != Stay || labels(m.List()) != "postgres" {
		t.Errorf("Esc in postgres gave %v and %q, want Stay and the database level", r, labels(m.List()))
	}
	m.Key(term.Key{Kind: term.KeyEsc})
	if r, _ := m.Key(term.Key{Kind: term.KeyEsc}); r != Back {
		t.Errorf("Esc at the top gave %v, want Back", r)
	}
}

// Esc with a search clears it and stays on the level.
func TestMenuEscClearsSearchFirst(t *testing.T) {
	m := NewMenu(testLeaves())
	pick(t, m, "host")
	typed(m.List(), "ex")
	if r, _ := m.Key(term.Key{Kind: term.KeyEsc}); r != Stay || labels(m.List()) != "exec,list" {
		t.Errorf("Esc with a search gave %v and %q, want the host level again", r, labels(m.List()))
	}
}

// Ctrl-C quits from any level.
func TestMenuInterrupt(t *testing.T) {
	m := NewMenu(testLeaves())
	pick(t, m, "host")
	if r, _ := m.Key(term.Key{Kind: term.KeyInterrupt}); r != Quit {
		t.Errorf("Ctrl-C gave %v, want Quit", r)
	}
}

// The question names where the person is.
func TestMenuQuestion(t *testing.T) {
	m := NewMenu(testLeaves())
	if got := m.List().Question; got != "Which command?" {
		t.Errorf("top question %q", got)
	}
	pick(t, m, "database")
	if got := m.List().Question; got != "komando database:" {
		t.Errorf("database question %q, want komando database:", got)
	}
}

// Every built leaf of the real table can be reached by its words and is
// taken as itself; nothing in the plan only is offered.
func TestMenuReachesEveryBuiltLeaf(t *testing.T) {
	all := capability.All()
	built := 0
	for _, want := range all {
		if want.State != capability.Built {
			continue
		}
		built++
		m := NewMenu(all)
		path := want.Key.Path()
		var r Result
		var got capability.Leaf
		for _, w := range path {
			r, got = pick(t, m, w)
		}
		if r == Stay { // a command with words after it
			r, got = pick(t, m, "this command")
		}
		if r != Take || got.Key != want.Key {
			t.Errorf("%s: the menu gave %v %q", want.Key, r, got.Key)
		}
	}
	if built == 0 {
		t.Fatal("no built leaf in the table")
	}
	m := NewMenu(all)
	var walk func(depth int)
	walk = func(depth int) {
		for _, row := range slices.Clone(m.List().Shown()) {
			r, l := pick(t, m, row.Label)
			if r == Take {
				if l.State != capability.Built {
					t.Errorf("%s is offered but not built", l.Key)
				}
				continue
			}
			walk(depth + 1)
			m.Key(term.Key{Kind: term.KeyEsc})
		}
	}
	walk(0)
}
