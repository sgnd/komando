package interactive

import (
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/cli/kit/term"
)

// Menu is the first screen: the command tree of the capability table as
// nested lists, one level per word a person types. Enter on a word opens
// the words after it; Enter on a whole command takes it.
type Menu struct {
	open []*node // the opened words, from the top
	list *List   // the level shown
}

// node is one word of the tree: a whole command (leaf), or words after it.
type node struct {
	word string
	leaf *capability.Leaf
	kids []*node
}

// NewMenu is the tree of the built leaves, at its top level.
func NewMenu(leaves []capability.Leaf) *Menu {
	root := &node{}
	for i := range leaves {
		if leaves[i].State != capability.Built {
			continue
		}
		n := root
		for _, w := range leaves[i].Key.Path() {
			n = n.child(w)
		}
		n.leaf = &leaves[i]
	}
	m := &Menu{open: []*node{root}}
	m.show()
	return m
}

// child is n's node for word, made when it is not there yet.
func (n *node) child(word string) *node {
	if k := n.kid(word); k != nil {
		return k
	}
	k := &node{word: word}
	n.kids = append(n.kids, k)
	return k
}

// List is the level shown, for Draw.
func (m *Menu) List() *List { return m.list }

// Key applies one key. Take comes with the leaf taken.
func (m *Menu) Key(k term.Key) (Result, capability.Leaf) {
	r, v := m.list.Key(k)
	switch r {
	case Take:
		if v == thisCommand {
			return Take, *m.top().leaf
		}
		n := m.top().kid(v)
		if len(n.kids) == 0 {
			return Take, *n.leaf
		}
		m.open = append(m.open, n)
		m.show()
	case Back:
		if len(m.open) == 1 {
			return Back, capability.Leaf{}
		}
		m.open = m.open[:len(m.open)-1]
		m.show()
	case Quit:
		return Quit, capability.Leaf{}
	}
	return Stay, capability.Leaf{}
}

func (m *Menu) top() *node { return m.open[len(m.open)-1] }

// thisCommand is the value of the row for the opened word's own command;
// no word of the tree is empty.
const thisCommand = ""

func (n *node) kid(word string) *node {
	for _, k := range n.kids {
		if k.word == word {
			return k
		}
	}
	return nil
}

// show makes the list of the opened level: its words in alphabetical
// order, each with what it is (a command's Short, or the words after it).
func (m *Menu) show() {
	n := m.top()
	kids := slices.Clone(n.kids)
	slices.SortFunc(kids, func(a, b *node) int { return strings.Compare(a.word, b.word) })
	var rows []Row
	if n.leaf != nil { // a command that also has words after it
		rows = append(rows, Row{Value: thisCommand, Label: "this command", Detail: n.leaf.Short})
	}
	for _, k := range kids {
		rows = append(rows, Row{Value: k.word, Label: k.word, Detail: k.detail()})
	}
	q := "Which command?"
	if len(m.open) > 1 {
		var words []string
		for _, o := range m.open[1:] {
			words = append(words, o.word)
		}
		q = "komando " + strings.Join(words, " ") + ":"
	}
	page := MaxRows
	if m.list != nil {
		page = m.list.page
	}
	m.list = NewList(q, "", rows, false)
	m.list.page = page
}

// detail is what a row says beside its word: a command's Short, or the
// words that come after it.
func (n *node) detail() string {
	if len(n.kids) == 0 {
		return n.leaf.Short
	}
	var words []string
	for _, k := range n.kids {
		words = append(words, k.word)
	}
	slices.Sort(words)
	return strings.Join(words, ", ")
}
