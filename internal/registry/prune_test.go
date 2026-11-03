package registry

import (
	"regexp"
	"testing"
	"time"
)

func TestPrunePlan(t *testing.T) {
	day := func(n int) time.Time { return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC) }
	tags := []TagInfo{
		{"v1", "sha256:a", day(1)},
		{"v2", "sha256:b", day(2)},
		{"v2-again", "sha256:b", day(2)}, // the same image under two tags
		{"v3", "sha256:c", day(3)},
		{"v4", "sha256:d", day(4)},
		{"stable", "sha256:a", day(1)}, // kept by --match, so v1's image stays
		{"latest", "sha256:d", day(4)},
		{"multi", "sha256:e", time.Time{}}, // no build date
	}
	plan := PruneRule{Keep: 1, Match: regexp.MustCompile(`^v`)}.Plan(tags)
	got := map[string][]string{}
	for _, d := range plan.Delete {
		got[d.Digest] = d.Tags
	}
	if len(plan.Delete) != 2 || len(got["sha256:b"]) != 2 || len(got["sha256:c"]) != 1 {
		t.Fatalf("delete %+v", plan.Delete)
	}
	why := map[string]string{}
	for _, k := range plan.Keep {
		why[k.Tag] = k.Reason
	}
	want := map[string]string{"v4": "one of the newest", "latest": "latest is always kept", "stable": "does not match",
		"multi": "does not match", "v1": "same image as the kept tag stable"}
	for tag, reason := range want {
		if why[tag] != reason {
			t.Errorf("%s kept as %q, want %q", tag, why[tag], reason)
		}
	}
	// a cutoff: only images built before it go
	plan = PruneRule{OlderThan: day(3)}.Plan(tags)
	for _, d := range plan.Delete {
		if !d.Created.Before(day(3)) {
			t.Errorf("deleted %v, built after the cutoff", d)
		}
	}
	if len(plan.Delete) != 2 || plan.Delete[0].Digest != "sha256:b" || plan.Delete[1].Digest != "sha256:a" || len(plan.Delete[1].Tags) != 2 {
		t.Errorf("cutoff plan %+v", plan.Delete)
	}
	if plan := (PruneRule{Keep: 100}).Plan(tags); len(plan.Delete) != 0 {
		t.Errorf("keep 100 deletes %+v", plan.Delete)
	}
}
