package cli

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sgnd/komando/internal/auditlog"
)

// A written record comes back as its JSON, and is read back in order,
// over more than one read step.
func TestSealedAuditPages(t *testing.T) {
	invHome(t)
	for i := range auditlog.Page + 1 {
		rec := map[string]any{"command": fmt.Sprintf("test.p%03d", i)}
		b, err := auditlog.Append(rec)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(rec)
		if string(b) != string(want) {
			t.Fatalf("written %s, want %s", b, want)
		}
	}
	var seqs []int
	if err := auditlog.Each(func(n int, _ []byte) error { seqs = append(seqs, n); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seqs) != auditlog.Page+1 || seqs[0] != 1 || seqs[auditlog.Page] != auditlog.Page+1 {
		t.Fatalf("read %d records, first %v", len(seqs), seqs[:1])
	}
	var after []int
	if err := auditlog.EachAfter(int64(auditlog.Page-1), func(n int, _ []byte) error { after = append(after, n); return nil }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(after) != fmt.Sprint([]int{auditlog.Page, auditlog.Page + 1}) {
		t.Fatalf("after %d: %v", auditlog.Page-1, after)
	}
	if n, err := auditlog.NewestSeq(); err != nil || n != int64(auditlog.Page+1) {
		t.Fatalf("newest %d %v", n, err)
	}
	if r, err := auditlog.Verify(); err != nil || !r.OK || r.Entries != auditlog.Page+1 {
		t.Fatalf("verify %+v %v", r, err)
	}
}
