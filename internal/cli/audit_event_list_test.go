package cli

import (
	"strings"
	"testing"
)

// Row C625 (1): auditEvent writes only an event of the closed list. A
// name that is not in it is a bug: no record is written under it, and the
// call warns that the audit log could not record it.
func TestAuditEventOutsideTheListRefused(t *testing.T) {
	invHome(t)
	noAgent(t)
	before := len(auditRecords(t))
	var e strings.Builder
	saved := tcl.out.Err
	tcl.out.Err = &e
	auditEvent(tcl, nil, "made.up", nil, "", true, nil)
	tcl.out.Err = saved
	if got := auditRecords(t); len(got) != before {
		t.Fatalf("a record was written for an event outside the list: %v", got[len(got)-1])
	}
	if !strings.Contains(e.String(), `"made.up" is not an audit event`) {
		t.Errorf("no warning: %q", e.String())
	}
}
