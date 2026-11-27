package cli

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
)

// gateFields are the fields of a gate: the four gate flags and who is
// calling. A write to a field of that name is a write to a gate, unless it
// is reviewed here as something else.
var gateFields = map[string]bool{"dryRun": true, "yes": true, "allowDangerous": true, "reveal": true, "parsed": true, "who": true, "hooks": true}

// programGateWriters is every place the program code of internal/cli stores
// a gate (g.Store), writes a gate's field, or makes a gate value (gate{}):
// newGate and noGate make the only two, startGate stores a new one when a
// command starts, withDryRun stores a copy with --dry-run on and puts the
// old one back, and asAgent stores a copy whose caller is an ssh-gate key.
// A new writer fails here until it is reviewed: it could turn --yes or
// --allow-dangerous on for a command the person never confirmed, or make
// an agent a person.
var programGateWriters = map[string]int{
	"call.go cl.g.Store":          3,
	"call.go cl.g.CompareAndSwap": 1,
	"call.go g.dryRun":            1,
	"call.go g.who":               1,
	"call.go gate{}":              2,
}

func TestGateWritersAreReviewed(t *testing.T) {
	got := gateWriters(t, false)
	if !maps.Equal(got, programGateWriters) {
		t.Errorf("the program code writes the gate at:\n%s\nwant:\n%s\na new or moved writer needs a review: it decides what komando lets through", writerLines(got), writerLines(programGateWriters))
	}
}

// testGateWriters is every place a test writes a gate: the helpers of
// testcall_test.go (setGate, savedFlags.restore, setTestCaller), and
// nowhere else, so a test never builds a gate the program could not.
var testGateWriters = map[string]int{
	"testcall_test.go cl.g.Store":       2,
	"testcall_test.go s.cl.g.Store":     1,
	"testcall_test.go g.allowDangerous": 1,
	"testcall_test.go g.dryRun":         1,
	"testcall_test.go g.reveal":         1,
	"testcall_test.go g.who":            1,
	"testcall_test.go g.yes":            1,
}

func TestTestsWriteTheGateThroughHelpers(t *testing.T) {
	got := gateWriters(t, true)
	if !maps.Equal(got, testGateWriters) {
		t.Errorf("the tests write the gate at:\n%s\nwant only the helpers of testcall_test.go:\n%s\nuse setGate, saveFlags, clearFlags or setTestCaller", writerLines(got), writerLines(testGateWriters))
	}
}

// gateWriters counts, per file and expression, the gate stores (x.g.Store),
// the writes to a gate field and the gate values made (gate{}, new(gate)) in
// the program files (tests false) or the test files (tests true) of
// internal/cli and the packages below it.
func gateWriters(t *testing.T, tests bool) map[string]int {
	t.Helper()
	got := map[string]int{}
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test != tests {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, l := range n.Lhs {
					if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && gateFields[sel.Sel.Name] {
						got[name+" "+types.ExprString(sel)]++
					}
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Store" || sel.Sel.Name == "CompareAndSwap" || sel.Sel.Name == "Swap") {
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "g" {
						got[name+" "+types.ExprString(inner)+"."+sel.Sel.Name]++
					}
				}
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
					if a, ok := n.Args[0].(*ast.Ident); ok && a.Name == "gate" {
						got[name+" gate{}"]++
					}
				}
			case *ast.CompositeLit:
				if id, ok := n.Type.(*ast.Ident); ok && id.Name == "gate" {
					got[name+" gate{}"]++
				}
			}
			return true
		})
	})
	return got
}

// gateFlagBindings: cobra binds the four gate flags in root.go without
// giving komando a pointer to what was typed (pf.Bool, the result dropped),
// and no program code reads them by name: newGate reads them, through
// gateFlagNames, when a command starts. So nothing can read or change a
// gate flag apart from the gate.
func TestGateFlagsAreParsedOnlyByTheGate(t *testing.T) {
	names := map[string]bool{}
	for _, n := range gateFlagNames {
		names[strconv.Quote(n)] = true
	}
	got := map[string]int{}
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test {
			return
		}
		dropped := map[*ast.CallExpr]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if es, ok := n.(*ast.ExprStmt); ok {
				if c, ok := es.X.(*ast.CallExpr); ok {
					dropped[c] = true
				}
			}
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, method := c.Fun.(*ast.SelectorExpr); !method {
				return true // a flag is read or bound through a method of cobra or pflag
			}
			for _, a := range c.Args {
				if lit, ok := a.(*ast.BasicLit); ok && names[lit.Value] {
					fn := types.ExprString(c.Fun)
					if dropped[c] {
						fn += " (result dropped)"
					}
					got[name+" "+fn+" "+lit.Value]++
				}
			}
			return true
		})
	})
	want := map[string]int{
		`root.go pf.Bool (result dropped) "dry-run"`:         1,
		`root.go pf.BoolP (result dropped) "yes"`:            1,
		`root.go pf.Bool (result dropped) "allow-dangerous"`: 1,
		`root.go pf.Bool (result dropped) "reveal"`:          1,
	}
	if !maps.Equal(got, want) {
		t.Errorf("calls that name a gate flag:\n%s\nwant only cobra's bindings, their results dropped:\n%s", writerLines(got), writerLines(want))
	}
}

// TestOneWayGateMethodsHaveTheirCallers: the gate changes during a command
// only at two reviewed places: kctl's diff turns --dry-run on (withDryRun)
// and the ssh gate's shell makes the key the caller (asAgent). A command
// starts its gate only from the root's hook (begin) and status --short,
// and the ssh gate reads a key's typed flags with newGate without storing it.
func TestOneWayGateMethodsHaveTheirCallers(t *testing.T) {
	watched := map[string]bool{"withDryRun": true, "asAgent": true, "startGate": true, "begin": true}
	got := map[string]int{}
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && watched[sel.Sel.Name] {
					got[name+" "+sel.Sel.Name]++
				}
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "newGate" {
					got[name+" newGate"]++
				}
			}
			return true
		})
	})
	want := map[string]int{
		"call.go begin":                     1, // newCall, with no command line yet
		"call.go startGate":                 1, // begin
		"root.go begin":                     1,
		"status.go startGate":               1,
		"cluster_kctl_change.go withDryRun": 1,
		"sshgate_shell.go asAgent":          1,
		"call.go newGate":                   1, // startGate
		"sshgate.go newGate":                1, // gateRule reads what a key typed; it stores no gate
	}
	if !maps.Equal(got, want) {
		t.Errorf("callers of begin, startGate, withDryRun and asAgent:\n%s\nwant:\n%s", writerLines(got), writerLines(want))
	}
}

// gateDeciders are the decisions the gate makes, as methods of *gate. The
// call keeps a forwarder of the same name for each, except
// personAllowsFlags, which only the gate's own decisions use.
var gateDeciders = []string{"yesOK", "yesOKFor", "dangerOK", "dangerAndYesOK", "revealOK",
	"personAllows", "personAllowsFor", "personAllowsFlags", "policyStop", "storeWrite"}

// TestDecisionsLoadTheGateOnce: each decision is a method of the gate, so
// it reads every flag and the caller from that one value and loads
// nothing; the call's forwarder of the same name loads the gate once.
func TestDecisionsLoadTheGateOnce(t *testing.T) {
	loads := map[string]bool{"gate": true, "dryRun": true, "yes": true, "allowDangerous": true, "reveal": true, "caller": true, "isAgent": true}
	onGate, onCall := map[string]int{}, map[string]int{}
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test {
			return
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || !slices.Contains(gateDeciders, fd.Name.Name) {
				continue
			}
			n := 0
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				if c, ok := x.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && loads[sel.Sel.Name] && len(c.Args) == 0 {
						n++
					}
				}
				return true
			})
			switch types.ExprString(fd.Recv.List[0].Type) {
			case "*gate":
				onGate[fd.Name.Name]++
				if n != 0 {
					t.Errorf("%s: (*gate).%s loads a gate %d times; read g's fields", name, fd.Name.Name, n)
				}
			case "*call":
				onCall[fd.Name.Name]++
				if n != 1 {
					t.Errorf("%s: (*call).%s loads the gate %d times; forward to cl.gate() once", name, fd.Name.Name, n)
				}
			}
		}
	})
	for _, d := range gateDeciders {
		if onGate[d] != 1 {
			t.Errorf("decision %s: %d methods on *gate, want 1", d, onGate[d])
		}
		if want := map[bool]int{true: 0, false: 1}[d == "personAllowsFlags"]; onCall[d] != want {
			t.Errorf("decision %s: %d forwarders on *call, want %d", d, onCall[d], want)
		}
	}
}

// gateMayCall is everything a method of the gate may call besides the
// gate's own methods, its hooks (g.hooks) and the approval session the
// hooks give it: pure helpers that neither write nor prompt.
var gateMayCall = map[string]bool{"append": true, "done": true, "flagKind": true, "tookGaveUp": true, "slices.ContainsFunc": true,
	"store.Preview": true, "store.Save": true, "g.who.IsAgent": true}

// TestGateOnlyDecides (Audit K2-0, condition 1): the gate decides; it does
// not write or prompt. A method of *gate reaches the call it decides for
// only through g.hooks, given to newGate and never set after
// (TestGateWritersAreReviewed), so it prints, records and asks only through
// them, and cli cannot swap them in the middle of a command.
func TestGateOnlyDecides(t *testing.T) {
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test {
			return
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || types.ExprString(fd.Recv.List[0].Type) != "*gate" || fd.Body == nil {
				continue
			}
			sess := map[string]bool{} // locals that hold g.hooks.approvals()
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				if as, ok := x.(*ast.AssignStmt); ok && len(as.Rhs) == 1 {
					if c, ok := as.Rhs[0].(*ast.CallExpr); ok && types.ExprString(c.Fun) == "g.hooks.approvals" {
						sess[types.ExprString(as.Lhs[0])] = true
					}
				}
				c, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := types.ExprString(c.Fun)
				if _, lit := c.Fun.(*ast.FuncLit); lit {
					return true
				}
				recv, _, _ := strings.Cut(fn, ".")
				switch {
				case gateMayCall[fn], strings.HasPrefix(fn, "g.hooks."), sess[recv]:
				case strings.HasPrefix(fn, "g.") && strings.Count(fn, ".") == 1:
				case strings.HasPrefix(fn, "func("), fn == "k" || fn == "f":
				default:
					t.Errorf("%s: (*gate).%s calls %s: the gate decides, it does not write or prompt; go through g.hooks", name, fd.Name.Name, fn)
				}
				return true
			})
		}
	})
}

// goFiles calls fn with every Go file of internal/cli and the packages
// below it, parsed, its slash path, and whether it is a test file.
func goFiles(t *testing.T, fn func(name string, test bool, file *ast.File)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(p), strings.HasSuffix(p, "_test.go"), file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// writerLines is m as sorted "file expression: count" lines.
func writerLines(m map[string]int) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		b.WriteString("  " + k + ": " + strconv.Itoa(m[k]) + "\n")
	}
	return b.String()
}

// TestNoGateIsNeverAPerson: a call reads a gate before any command starts,
// and a call made without newCall has none stored. Neither is ever a
// person with a flag on: newCall stores a gate from the call's own
// environment, and a call with no gate reads as an AI agent, every flag off.
func TestNoGateIsNeverAPerson(t *testing.T) {
	if testCall().g.Load() == nil {
		t.Fatal("newCall stored no gate")
	}
	var bare call
	g := bare.gate()
	if !g.who.IsAgent() || g.dryRun || g.yes || g.allowDangerous || g.reveal {
		t.Errorf("a call without a gate reads %+v; want an AI agent with every flag off", *g)
	}
	if g.personAllows("--yes") || g.personAllowsFor("--allow-dangerous", "runs `x`") {
		t.Error("a gate without hooks let an agent's flag through; it has no window to ask in, so it must refuse")
	}
	if got := newGate(nil, engine.Caller{Kind: engine.Script}, nil); got.who.Kind != engine.Script || got.dryRun || got.yes || got.allowDangerous || got.reveal {
		t.Errorf("newGate with no command line = %+v; want the caller it was given and every flag off", *got)
	}
}

// TestAsAgentIsOneWay: asAgent makes the caller the ssh-gate key, an AI
// agent, from a person, a script or another agent; it keeps the Actor (who
// owns runs and sessions, and whom the audit log names) and changes no
// gate flag.
func TestAsAgentIsOneWay(t *testing.T) {
	for _, from := range []engine.Caller{
		{Kind: engine.Person, Actor: "alice"},
		{Kind: engine.Script, Actor: "cron"},
		{Kind: engine.Agent, Agent: "Claude Code", Actor: "bob"},
	} {
		for _, on := range []bool{false, true} {
			cl := testCall()
			setTestCaller(cl, from)
			setGate(cl, on, gateDryRun, gateYes, gateAllowDangerous, gateReveal)
			before := *cl.gate()
			cl.asAgent("deploy-key")
			got := *cl.gate()
			want := engine.Caller{Kind: engine.Agent, Agent: "ssh-gate key deploy-key", Actor: from.Actor}
			if got.who != want {
				t.Errorf("from %+v: caller %+v, want %+v", from, got.who, want)
			}
			if got.dryRun != before.dryRun || got.yes != before.yes || got.allowDangerous != before.allowDangerous || got.reveal != before.reveal {
				t.Errorf("from %+v, flags %v: asAgent changed a gate flag: %+v, was %+v", from, on, got, before)
			}
		}
	}
}

// TestAsAgentAfterPersonAllowed: decisions read the caller when they are
// made. A person's --allow-dangerous counts without a window; once the
// command's caller became an ssh-gate key, the same flag needs a person's
// yes in the window, and a no stops it.
func TestAsAgentAfterPersonAllowed(t *testing.T) {
	cl := testCall()
	setTestCaller(cl, engine.Caller{Kind: engine.Person, Actor: "alice"})
	setGate(cl, true, gateAllowDangerous)
	asks := 0
	cl.ask = func(string) (allowed, shown bool) { asks++; return false, true }
	if !cl.dangerOK("rm -rf on web1") || asks != 0 {
		t.Fatalf("a person's --allow-dangerous: ok %v after %d windows; want ok with none", cl.dangerOK("rm -rf on web1"), asks)
	}
	cl.asAgent("deploy-key")
	if cl.dangerOK("rm -rf on web1") {
		t.Errorf("after asAgent, --allow-dangerous counted although the window said no (%d windows)", asks)
	}
}

// TestWithDryRunOnlyTurnsDryRunOn: kctl's diff runs its apply with
// --dry-run on; nothing else of the gate changes, f's error comes back,
// and the gate is the one from before afterwards.
func TestWithDryRunOnlyTurnsDryRunOn(t *testing.T) {
	cl := testCall()
	setTestCaller(cl, engine.Caller{Kind: engine.Agent, Agent: "Claude Code", Actor: "bob"})
	setGate(cl, true, gateReveal) // --yes and --allow-dangerous stay off
	before := cl.gate()
	want := errors.New("server said no")
	err := cl.withDryRun(func() error {
		g := cl.gate()
		if !g.dryRun {
			t.Error("inside withDryRun --dry-run is off")
		}
		if g.yes != before.yes || g.allowDangerous != before.allowDangerous || g.reveal != before.reveal || g.who != before.who {
			t.Errorf("withDryRun changed more than --dry-run: %+v, was %+v", *g, *before)
		}
		return want
	})
	if err != want {
		t.Errorf("withDryRun returned %v, want f's error", err)
	}
	if cl.gate() != before {
		t.Errorf("after withDryRun the gate is %+v, want the one from before %+v", *cl.gate(), *before)
	}
}

// TestStatusShortHasItsOwnGate: status --short skips the root's checks,
// not its own gate: it runs with the flags of its own command line and the
// caller read again from the environment, never the ones of the command
// before it in the call.
func TestStatusShortHasItsOwnGate(t *testing.T) {
	invHome(t)
	noAgent(t)
	c := processCall()
	c.Stdout, c.Stderr = io.Discard, io.Discard
	cl := newCall(c, nil)
	t.Setenv("KOMANDO_AGENT", "1") // the next command is an agent's
	defer store.Close()
	if code := execute(cl, context.Background(), []string{"--dry-run", "status", "--short"}); code != 0 {
		t.Fatalf("komando status --short: exit %d", code)
	}
	if !cl.isAgent() || !cl.dryRun() {
		t.Errorf("status --short ran as agent %v with --dry-run %v; want its own gate: an agent, --dry-run on", cl.isAgent(), cl.dryRun())
	}
}

// TestEachCallRunsOneCommand: a call runs one command: the komando program
// (Execute) and an app (RunCall) each make a new call and run it once, and
// nothing else starts a command (execute through runCall). So the gate a
// command's goroutines read is the one its begin stored, until the call
// ends: no goroutine of a command can read the gate of a later command in
// the same call, and none needs to keep its own copy. A loop that runs
// several commands in one call fails here, and must first give each
// command's goroutines the gate of their own command.
func TestEachCallRunsOneCommand(t *testing.T) {
	watched := map[string]bool{"runCall": true, "runExecute": true, "execute": true, "newCall": true}
	got := map[string]int{}
	goFiles(t, func(name string, test bool, file *ast.File) {
		if test {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && watched[id.Name] {
					got[name+" "+id.Name]++
				}
			}
			return true
		})
	})
	want := map[string]int{
		"call.go newCall":    3, // Execute, RunCall, treeCall (a tree that is never run)
		"call.go runCall":    2, // Execute, RunCall: each with the call it just made
		"call.go runExecute": 1, // runCall
	}
	if !maps.Equal(got, want) {
		t.Errorf("where calls are made and commands run:\n%s\nwant:\n%s", writerLines(got), writerLines(want))
	}
}

// TestGlobalFlagsHoldNoGateFlag (Audit A-444-1): the gate flags live only
// in the gate. The call's global flags have no field for them, nor a gate,
// so a copy of the whole value (f := cl.flags) cannot carry one past the
// gate's methods and the scans above.
func TestGlobalFlagsHoldNoGateFlag(t *testing.T) {
	ft := reflect.TypeFor[globalFlags]()
	for i := range ft.NumField() {
		f := ft.Field(i)
		if gateFields[f.Name] || f.Type == reflect.TypeFor[gate]() || f.Type == reflect.TypeFor[*gate]() {
			t.Errorf("globalFlags has %s %s: the gate flags and the caller belong to the gate only", f.Name, f.Type)
		}
	}
}

// TestWithDryRunKeepsAGateStoredMeanwhile (Audit A-445-1): a gate stored
// while withDryRun's f runs (an asAgent inside it) is not overwritten when
// withDryRun puts its gate back: the caller stays the ssh-gate key, with
// --dry-run still on.
func TestWithDryRunKeepsAGateStoredMeanwhile(t *testing.T) {
	cl := testCall()
	setTestCaller(cl, engine.Caller{Kind: engine.Person, Actor: "alice"})
	if err := cl.withDryRun(func() error { cl.asAgent("deploy-key"); return nil }); err != nil {
		t.Fatal(err)
	}
	g := cl.gate()
	if want := (engine.Caller{Kind: engine.Agent, Agent: "ssh-gate key deploy-key", Actor: "alice"}); g.who != want || !g.dryRun {
		t.Errorf("after withDryRun: caller %+v, --dry-run %v; want the asAgent caller %+v kept, --dry-run on", g.who, g.dryRun, want)
	}
}
