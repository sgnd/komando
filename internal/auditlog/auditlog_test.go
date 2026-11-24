package auditlog

import "testing"

// The text of `komando audit verify`, for an intact and a broken log.
func TestAuditCheckText(t *testing.T) {
	ok := Check{OK: true, Entries: 3, Note: "n"}
	if got := ok.Text(); got != "audit log intact: 3 entries\nn" {
		t.Errorf("intact: %q", got)
	}
	bad := Check{FirstBroken: 2, Note: "n"}
	if got := bad.Text(); got != "audit log broken at line 2\nn" {
		t.Errorf("broken: %q", got)
	}
}
