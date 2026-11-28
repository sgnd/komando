package cli

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Row C625 (1), audit A5: an event name outside the closed list is a bug.
// The audit never fails open: the record is written, without event and
// with event_invalid naming it, and the call warns. Under test the bug
// panics (TestAuditEventOutsideTheListPanicsUnderTest).
func TestAuditEventOutsideTheListRecorded(t *testing.T) {
	invHome(t)
	noAgent(t)
	saved := auditEventBug
	t.Cleanup(func() { auditEventBug = saved })
	auditEventBug = func(string) {}
	before := len(auditRecords(t))
	var e strings.Builder
	savedErr := tcl.out.Err
	tcl.out.Err = &e
	auditEvent(tcl, nil, "made.up", nil, "", true, map[string]any{"x": 1})
	tcl.out.Err = savedErr
	got := auditRecords(t)
	if len(got) != before+1 {
		t.Fatalf("records %d, want %d: the record was dropped", len(got), before+1)
	}
	r := got[len(got)-1]
	if _, has := r["event"]; has || r["event_invalid"] != "made.up" || r["x"] != float64(1) {
		t.Errorf("record %v, want event_invalid made.up and no event", r)
	}
	if !strings.Contains(e.String(), `"made.up" is not an audit event`) {
		t.Errorf("no warning: %q", e.String())
	}
}

func TestAuditEventOutsideTheListPanicsUnderTest(t *testing.T) {
	invHome(t)
	noAgent(t)
	defer func() {
		if recover() == nil {
			t.Error("an event outside the list did not panic under test")
		}
	}()
	auditEvent(tcl, nil, "made.up", nil, "", true, nil)
}

// testingImports are the production files that still import the testing
// package; the list may only shrink. A hook the tests need is a package
// variable TestMain sets (auditEventBug), never testing.Testing (audit T6).
var testingImports = []string{"prompter.go"}

func TestProductionCodeImportsNoTesting(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "testing" && !slices.Contains(testingImports, f) {
				t.Errorf("%s imports testing: give the tests a hook that TestMain sets", f)
			}
		}
	}
}
