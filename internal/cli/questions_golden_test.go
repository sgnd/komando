package cli

import (
	"fmt"
	"strings"
	"testing"
)

// TestQuestionsGolden pins every question a person at a terminal can be
// asked: the questions of each command typed with something missing, and
// the questions of every add form. The capability table takes them over
// later; this recording shows that nothing was lost on the way.
func TestQuestionsGolden(t *testing.T) {
	if testing.Short() || raceOn {
		t.Skip("builds the questions of every command")
	}
	var b strings.Builder
	root := newRoot(tcl)
	for _, path := range visiblePaths(root) {
		c, _, err := root.Find(path)
		if err != nil || !c.Runnable() || len(path) == 0 {
			continue
		}
		writeQuestions(&b, "komando "+strings.Join(path, " "), formCmdSpec(c))
	}
	for _, g := range formGroups(tcl) {
		for _, k := range g.kinds {
			writeQuestions(&b, "add form: "+g.label+" / "+k.label, k.spec(tcl))
		}
	}
	matchGolden(t, "testdata/questions_golden.txt", b.String())
}

// writeQuestions writes what a person reads of each question; the
// functions behind a question (choices, checks) are noted, not called.
func writeQuestions(b *strings.Builder, head string, sp formSpec) {
	fmt.Fprintf(b, "### %s\ntitle: %s\n", head, sp.title)
	for _, q := range sp.qs {
		var marks []string
		for _, m := range []struct {
			on   bool
			name string
		}{{q.optional, "optional"}, {q.advanced, "advanced"}, {q.addr, "addr"}, {q.free, "free"},
			{q.def != nil, "default"}, {q.choices != nil, "choices"}, {q.show != nil, "show"},
			{q.when != nil, "when"}, {q.check != nil, "check"}} {
			if m.on {
				marks = append(marks, m.name)
			}
		}
		fmt.Fprintf(b, "- %s | %s | %s | %s | %s | %s\n", q.key, q.label, q.ask, q.help, q.example, strings.Join(marks, ","))
	}
}
