package cli

import (
	"slices"
	"strings"
	"testing"
)

// group rm GROUP T1 T2 takes only T1 and T2 out of the group; the other
// members stay, and the group is not deleted.
func TestGroupRmSeveralTargets(t *testing.T) {
	invHome(t)
	for _, h := range []string{"w1", "w2", "w3"} {
		mustRun(t, "host", "add", h, "u@10.0.0.1", "-g", "web")
	}
	d := mustRun(t, "group", "rm", "web", "w1", "w2")
	got := []string{}
	for _, r := range d["removed"].([]any) {
		got = append(got, r.(string))
	}
	if !slices.Equal(got, []string{"w1", "w2"}) {
		t.Errorf("removed %v, want w1 w2", got)
	}
	if l := mustRun(t, "host", "show", "w3"); !strings.Contains(stringOf(l), "web") {
		t.Errorf("w3 left the group: %v", l)
	}
}
