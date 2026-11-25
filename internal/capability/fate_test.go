package capability

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The tests below read today's tables from internal/cli's source, so the
// pre-cut fields cannot drift from the code they stand in for.
const cliDir = "../cli/"

func todayIDs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/v0_17_ids.txt") // frozen: the cut renames internal/cli's list
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// carriers maps each of today's IDs to the leaves that carry it.
func carriers() map[string][]Leaf {
	m := map[string][]Leaf{}
	for _, l := range All() {
		for _, id := range append(slices.Clone(l.Today), l.Carries...) {
			m[id] = append(m[id], l)
		}
	}
	return m
}

// TestEveryIDHasFate is the "nothing lost" check of the cut (plan section
// 1): every command ID of today has exactly one fate (a leaf carries it,
// gone, internal, cobra's own, or a group), no fate list names an ID
// twice, and the leaves that carry one ID share their verb and type: they
// differ only in provider or area (one leaf per provider, or one ID that
// splits into kinds; conn splits into types).
func TestEveryIDHasFate(t *testing.T) {
	ids := todayIDs(t)
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	fate := map[string][]string{} // ID -> where its fate is written
	add := func(id, where string) {
		if slices.Contains(fate[id], where) {
			t.Errorf("%s: listed twice in %s", id, where)
		}
		fate[id] = append(fate[id], where)
	}
	for _, l := range All() {
		for _, id := range slices.Concat(l.Today, l.Carries) {
			add(id, "leaf "+l.Key.String())
		}
	}
	for _, g := range Gones() {
		add(g.Today, "gone")
	}
	for _, in := range Internals() {
		add(in.Today, "internal")
	}
	for _, id := range CobraOwn() {
		add(id, "cobra")
	}
	for _, id := range Groups() {
		add(id, "group")
		if k, ok := todayOnlyKeys[id]; !ok || k.Verb != "" {
			t.Errorf("%s: in groups, but its key in todayOnlyKeys is %v, not a group's (no verb)", id, k)
		}
		if !slices.ContainsFunc(ids, func(other string) bool { return strings.HasPrefix(other, id+".") }) {
			t.Errorf("%s: in groups, but no command ID of today is under it", id)
		}
	}
	for id, where := range fate {
		if !known[id] {
			t.Errorf("%s (%v): not a command ID of today", id, where)
		}
		kinds := map[string]bool{}
		for _, w := range where {
			kinds[strings.Fields(w)[0]] = true
		}
		if len(kinds) > 1 {
			t.Errorf("%s: two kinds of fate %v", id, where)
		}
	}
	for id, ls := range carriers() {
		for _, l := range ls[1:] {
			// conn of today holds entries of every type; v2.7 puts them under each
			splitsByType := strings.HasPrefix(id, "conn.")
			if l.Verb != ls[0].Verb || l.Type != ls[0].Type && !splitsByType {
				t.Errorf("%s: carried by %s and %s, two different commands", id, ls[0].Key, l.Key)
			}
		}
	}
	for _, id := range ids {
		if len(fate[id]) == 0 {
			t.Errorf("%s: no fate: carry it on a leaf (Today or Carries), or add it to gone, internal, cobraOwn or groups", id)
		}
	}
}

func TestInternalForLeaf(t *testing.T) {
	for _, in := range Internals() {
		found := false
		for _, l := range All() {
			k := l.Key
			if in.For.Provider == "" {
				k.Provider = ""
			}
			if k == in.For {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: serves %s, which no leaf has", in.Today, in.For)
		}
	}
}

// ownDataAreas list komando's own state, not the target's.
var ownDataAreas = []Key{
	{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "list"},
	{Type: "cluster", Provider: "kubernetes", Area: "tunnel", Verb: "list"},
}

func TestLeafKeepsMasking(t *testing.T) {
	personal := mapLiteralKeys(t, cliDir+"personal.go", "personalCmds")
	for _, l := range All() {
		for _, id := range append(slices.Clone(l.Today), l.Carries...) {
			if personal[strings.ReplaceAll(id, ".", " ")] && l.Output != TargetData {
				t.Errorf("%s: carries %s, whose output is masked today (personalCmds), but is not TargetData", l.Key, id)
			}
		}
		if mustMask(l) && l.Output != TargetData {
			t.Errorf("%s: prints what it reads from a target, but is not TargetData", l.Key)
		}
	}
}

func mustMask(l Leaf) bool {
	if slices.Contains(ownDataAreas, l.Key) {
		return false
	}
	if slices.Contains([]string{"query", "raw", "exec", "copy"}, l.Verb) {
		return true
	}
	return l.Area != "" && slices.Contains(targetTypes, l.Type) && slices.Contains([]string{"read", "list", "show"}, l.Verb)
}

// storeOptional are the IDs checkStoreWritable (internal/cli/root.go) lets
// run without a writable store besides localReads and their top words.
var storeOptional = []string{"help", "completion", "secret.passphrase"}

func TestLocalReadsKept(t *testing.T) {
	local := mapLiteralKeys(t, cliDir+"root.go", "localReads")
	for _, l := range All() {
		for _, id := range append(slices.Clone(l.Today), l.Carries...) {
			top, _, _ := strings.Cut(id, ".")
			if (local[id] || local[top] || slices.Contains(storeOptional, id)) && !l.LocalRead {
				t.Errorf("%s: carries %s, which runs without a writable store today (localReads), but is not LocalRead", l.Key, id)
			}
		}
	}
}

func TestLeavesHomeKept(t *testing.T) {
	home := mapLiteralKeys(t, cliDir+"root.go", "leavesHome")
	for _, l := range All() {
		for _, id := range append(slices.Clone(l.Today), l.Carries...) {
			if home[id] && !l.LeavesHome {
				t.Errorf("%s: carries %s, which run as root never touches ~/.komando (leavesHome), but is not LeavesHome", l.Key, id)
			}
		}
	}
}

// TestTodayKeys: every command ID of today has one safety key, taken from
// the leaf that keeps it under its own key (Today) or from todayOnlyKeys,
// never from both; an ID a leaf carries under another key (Carries) has a
// key that is not that leaf's.
func TestTodayKeys(t *testing.T) {
	keys := TodayKeys()
	for _, id := range todayIDs(t) {
		if _, ok := keys[id]; !ok {
			t.Errorf("%s: no safety key", id)
		}
	}
	if len(keys) != len(todayIDs(t)) {
		t.Errorf("%d keys for %d command IDs", len(keys), len(todayIDs(t)))
	}
	for _, l := range All() {
		own := TodayKey{l.Type, l.Area, l.Verb}
		for _, id := range l.Today {
			if _, dup := todayOnlyKeys[id]; dup {
				t.Errorf("%s: %s is in Today and in todayOnlyKeys", l.Key, id)
			}
		}
		for _, id := range l.Carries {
			if keys[id] == own {
				t.Errorf("%s: Carries has %s, whose key is this leaf's: move it to Today", l.Key, id)
			}
		}
	}
}

// mapLiteralKeys returns the string keys of the map literal assigned to
// the package-level var name in file.
func mapLiteralKeys(t *testing.T, file, name string) map[string]bool {
	t.Helper()
	lit, err := varLiteral(file, name)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if s, ok := stringLit(kv.Key); ok {
			keys[s] = true
		}
	}
	if len(keys) == 0 {
		t.Fatalf("%s: %s has no string keys", file, name)
	}
	return keys
}

func varLiteral(file, name string) (*ast.CompositeLit, error) {
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, s := range g.Specs {
			v, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, n := range v.Names {
				if n.Name != name || i >= len(v.Values) {
					continue
				}
				if lit, ok := v.Values[i].(*ast.CompositeLit); ok {
					return lit, nil
				}
			}
		}
	}
	return nil, errors.New(file + ": no var " + name + " with a literal value")
}

func stringLit(e ast.Expr) (string, bool) {
	b, ok := e.(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(b.Value)
	return s, err == nil
}
