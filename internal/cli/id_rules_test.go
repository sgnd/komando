package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/policy"
)

// TestReplacedIDsNameTheirRules reads the cut plan's "Carried by" column
// for every command of today that exec, query or raw does after the cut
// (capability.Replacements) and checks it against the code:
//   - the list holds exactly the IDs an exec, query or raw leaf carries;
//   - each ID names a carrier: a v2.7 tier row, a policy rule or a stop;
//   - each named row reaches a leaf that carries the ID, each rule is in
//     policy.Rules() (a SQL rule in driver.SQLRules()), each test and
//     stop is a function in this module, and one of the ID's tests names
//     each of its rules;
//   - an ID that is dangerous today keeps a dangerous carrier: a policy
//     or SQL rule on a leaf with a dangerous row, or a dangerous row that rates
//     the text itself (byValueRows);
//   - an ID with no rule says why (NoRule).
func TestReplacedIDsNameTheirRules(t *testing.T) {
	rules := map[string]bool{}
	for _, r := range policy.Rules() {
		rules[r.ID] = true
	}
	sqlRules := map[string]bool{}
	for _, r := range driver.SQLRules() {
		sqlRules[r.ID] = true
	}
	funcs := moduleFuncs(t)
	carriers := replacedCarriers()
	seen := map[string]bool{}
	for _, r := range capability.Replacements() {
		if seen[r.Today] {
			t.Errorf("%s: listed twice in capability.Replacements", r.Today)
			continue
		}
		seen[r.Today] = true
		leaves, ok := carriers[r.Today]
		if !ok {
			t.Errorf("%s: in capability.Replacements, but no exec, query or raw leaf carries it", r.Today)
			continue
		}
		for _, why := range replacedGaps(r, leaves, rules, sqlRules, funcs) {
			t.Errorf("%s (highest row today %s): %s", r.Today, todayTier(cmdKeys[r.Today]), why)
		}
	}
	for id := range carriers {
		if !seen[id] {
			t.Errorf("%s: carried by an exec, query or raw leaf, but not in capability.Replacements", id)
		}
	}
}

// replacedVerbs are the verbs of the leaves that replace today's commands.
var replacedVerbs = []string{"host", "ssh", "exec", "query", "raw"}

// byValueRows are the dynamic rows whose leaf rates the text itself (the
// cache command, the SQL, the cluster command), so the row alone keeps a
// dangerous command dangerous. host exec's row holds only when a policy
// rule matches, so an exec ID must name its rules.
var byValueRows = []capability.Key{
	{Type: "cache", Verb: "raw"},
	{Type: "cluster", Verb: "raw"},
	{Type: "database", Verb: "query"},
}

// replacedCarriers maps each ID an exec, query or raw leaf carries to
// those leaves.
func replacedCarriers() map[string][]capability.Key {
	m := map[string][]capability.Key{}
	for _, l := range capability.All() {
		if !slices.Contains(replacedVerbs, l.Verb) {
			continue
		}
		for _, id := range l.Carries {
			m[id] = append(m[id], l.Key)
		}
	}
	return m
}

// replacedGaps says what is wrong with one entry, or nothing.
func replacedGaps(r capability.Replaced, leaves []capability.Key, rules, sqlRules map[string]bool, funcs map[string][]moduleFunc) []string {
	var out []string
	if len(r.Rows)+len(r.Rules)+len(r.SQLRules)+len(r.Stops) == 0 && !r.EveryRule {
		out = append(out, "names no carrier (row, rule or stop)")
	}
	strongest := capability.Read
	for _, k := range r.Rows {
		tier, why := namedRowTier(k, leaves)
		if why != "" {
			out = append(out, why)
		}
		strongest = max(strongest, tier)
	}
	hasRule := len(r.Rules)+len(r.SQLRules) > 0 || r.EveryRule
	for _, id := range r.SQLRules {
		if !sqlRules[id] {
			out = append(out, "SQL rule "+id+" is not in driver.SQLRules()")
		}
	}
	for _, id := range slices.Concat(r.Rules, r.SQLRules) {
		if !rules[id] && !slices.Contains(r.SQLRules, id) {
			out = append(out, "rule "+id+" is not in policy.Rules()")
		}
		if !slices.ContainsFunc(r.Tests, func(tn string) bool { return testNames(funcs[tn], id) }) {
			out = append(out, "rule "+id+": none of its tests "+strings.Join(r.Tests, ", ")+" names it")
		}
	}
	if hasRule && len(r.Tests) == 0 {
		out = append(out, "names rules but no test")
	}
	if hasRule && slices.ContainsFunc(leaves, func(k capability.Key) bool { return leafTier(k) >= capability.Dangerous }) {
		strongest = max(strongest, capability.Dangerous)
	}
	for _, tn := range r.Tests {
		if !strings.HasPrefix(tn, "Test") || !slices.ContainsFunc(funcs[tn], func(f moduleFunc) bool { return f.test }) {
			out = append(out, "test "+tn+" is no Test function in this module")
		}
	}
	for _, s := range r.Stops {
		if !slices.ContainsFunc(funcs[s], func(f moduleFunc) bool { return !f.test }) {
			out = append(out, "stop "+s+" is no function in this module")
		}
	}
	switch {
	case hasRule && r.NoRule != "":
		out = append(out, "names rules and also says why it has none (NoRule)")
	case !hasRule && strings.TrimSpace(r.NoRule) == "":
		out = append(out, "names no rule and does not say why (NoRule)")
	}
	if int(todayTier(cmdKeys[r.Today])) >= int(capability.Dangerous) && int(strongest) < int(capability.Dangerous) {
		out = append(out, "dangerous today, but its strongest carrier is "+tier(strongest).String())
	}
	return out
}

// namedRowTier is the tier a named row keeps for the ID: the highest row
// with exactly this key that reaches one of its leaves. A dynamic row
// counts only when its leaf rates the text itself (byValueRows).
func namedRowTier(k capability.Key, leaves []capability.Key) (capability.Tier, string) {
	best, found := capability.Read, false
	for _, row := range capability.TierRows() {
		if row.Key != k || !slices.ContainsFunc(leaves, row.Reaches) {
			continue
		}
		found = true
		if row.Dynamic == "" || slices.Contains(byValueRows, k) {
			best = max(best, row.Tier)
		}
	}
	if !found {
		return best, "row " + k.String() + " is no tier row that reaches " + keysString(leaves)
	}
	return best, ""
}

func keysString(ks []capability.Key) string {
	var s []string
	for _, k := range ks {
		s = append(s, k.String())
	}
	return strings.Join(s, ", ")
}

// moduleFunc is one function declared in the module (methods left out).
type moduleFunc struct {
	test bool
	body *ast.BlockStmt
}

// moduleFuncs parses every Go file of the module, tests included, and
// indexes its functions by name.
func moduleFuncs(t *testing.T) map[string][]moduleFunc {
	t.Helper()
	m := map[string][]moduleFunc{}
	fset := token.NewFileSet()
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				m[fn.Name.Name] = append(m[fn.Name.Name], moduleFunc{test: strings.HasSuffix(p, "_test.go"), body: fn.Body})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m["TestReplacedIDsNameTheirRules"]) == 0 {
		t.Fatal("moduleFuncs did not find this test: the module root is wrong")
	}
	return m
}

// testNames reports whether one of these test functions has the string
// literal id in its body.
func testNames(fns []moduleFunc, id string) bool {
	for _, f := range fns {
		if !f.test || f.body == nil {
			continue
		}
		found := false
		ast.Inspect(f.body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil && s == id {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
