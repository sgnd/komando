package capability

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
	b, err := os.ReadFile(cliDir + "testdata/command_ids.txt")
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

func TestEveryIDHasFate(t *testing.T) {
	ids := todayIDs(t)
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	fate := map[string][]string{} // ID -> where its fate is written
	for id, ls := range carriers() {
		for _, l := range ls {
			fate[id] = append(fate[id], "leaf "+l.Key.String())
		}
	}
	for _, g := range Gones() {
		fate[g.Today] = append(fate[g.Today], "gone")
	}
	for _, in := range Internals() {
		fate[in.Today] = append(fate[in.Today], "internal")
	}
	for _, id := range CobraOwn() {
		fate[id] = append(fate[id], "cobra")
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
	for _, id := range ids {
		if len(fate[id]) > 0 {
			continue
		}
		// a group of today (db.user) needs no fate of its own when every
		// command under it has one
		group := slices.ContainsFunc(ids, func(other string) bool { return strings.HasPrefix(other, id+".") })
		if !group {
			t.Errorf("%s: no fate: carry it on a leaf (Today or Carries), or add it to gone, internal or cobraOwn", id)
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

func TestLocalReadsKept(t *testing.T) {
	local := mapLiteralKeys(t, cliDir+"root.go", "localReads")
	for _, l := range All() {
		for _, id := range append(slices.Clone(l.Today), l.Carries...) {
			if local[id] && !l.LocalRead {
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

// TestTodayMapAgrees: internal/cli keys today's safety rows by cmdKeys. A leaf's
// Today is exactly the IDs whose key is the leaf's (type, area, verb);
// everything else it does is in Carries.
func TestTodayMapAgrees(t *testing.T) {
	keys, err := cmdKeys(cliDir + "risk_keys.go")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("internal/cli/risk_keys.go (cmdKeys) is not on this branch yet; this test runs once it is")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range All() {
		own := [3]string{l.Type, l.Area, l.Verb}
		for _, id := range l.Today {
			if k, ok := keys[id]; !ok || k != own {
				t.Errorf("%s: Today has %s, but cmdKeys gives %v (in cmdKeys: %v)", l.Key, id, k, ok)
			}
		}
		for _, id := range l.Carries {
			if keys[id] == own {
				t.Errorf("%s: Carries has %s, whose cmdKeys key is this leaf's: move it to Today", l.Key, id)
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

// cmdKeys reads internal/cli's map from command ID to safetyKey{typ, area, verb}.
func cmdKeys(file string) (map[string][3]string, error) {
	lit, err := varLiteral(file, "cmdKeys")
	if err != nil {
		return nil, err
	}
	keys := map[string][3]string{}
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, ok := stringLit(kv.Key)
		val, ok2 := kv.Value.(*ast.CompositeLit)
		if !ok || !ok2 || len(val.Elts) != 3 {
			return nil, errors.New(file + ": a cmdKeys entry is not \"ID\": {typ, area, verb}")
		}
		var k [3]string
		for i, part := range val.Elts {
			if k[i], ok = stringLit(part); !ok {
				return nil, errors.New(file + ": cmdKeys " + id + ": not three strings")
			}
		}
		keys[id] = k
	}
	return keys, nil
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
