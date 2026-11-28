package cli

import (
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
