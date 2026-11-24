package cli

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The text of `komando audit verify`, for an intact and a broken log.
func TestAuditCheckText(t *testing.T) {
	ok := auditCheck{OK: true, Entries: 3, Note: "n"}
	if got := ok.Text(); got != "audit log intact: 3 entries\nn" {
		t.Errorf("intact: %q", got)
	}
	bad := auditCheck{FirstBroken: 2, Note: "n"}
	if got := bad.Text(); got != "audit log broken at line 2\nn" {
		t.Errorf("broken: %q", got)
	}
}

// A written record comes back as its JSON, and is read back in order,
// over more than one read step.
func TestSealedAuditPages(t *testing.T) {
	invHome(t)
	for i := range auditPage + 1 {
		rec := map[string]any{"command": fmt.Sprintf("test.p%03d", i)}
		b, err := writeSealedAudit(rec)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(rec)
		if string(b) != string(want) {
			t.Fatalf("written %s, want %s", b, want)
		}
	}
	var seqs []int
	if err := eachAudit(func(n int, _ []byte) error { seqs = append(seqs, n); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seqs) != auditPage+1 || seqs[0] != 1 || seqs[auditPage] != auditPage+1 {
		t.Fatalf("read %d records, first %v", len(seqs), seqs[:1])
	}
	var after []int
	if err := eachAuditAfter(int64(auditPage-1), func(n int, _ []byte) error { after = append(after, n); return nil }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(after) != fmt.Sprint([]int{auditPage, auditPage + 1}) {
		t.Fatalf("after %d: %v", auditPage-1, after)
	}
	if n, err := newestAuditSeq(); err != nil || n != int64(auditPage+1) {
		t.Fatalf("newest %d %v", n, err)
	}
	if r, err := verifySealedAudit(); err != nil || !r.OK || r.Entries != auditPage+1 {
		t.Fatalf("verify %+v %v", r, err)
	}
}
