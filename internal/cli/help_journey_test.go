package cli

import (
	"strings"
	"testing"
)

func TestUsedByText(t *testing.T) {
	if got := usedByText([]string{"a", "b"}); got != "a,b" {
		t.Errorf("short: %q", got)
	}
	if got := usedByText([]string{"app-01", "app-02", "c", "d"}); got != "4 (app-01, app-02, +2)" {
		t.Errorf("long: %q", got)
	}
}

func TestGuideSections(t *testing.T) {
	for _, topic := range guideTopics {
		if s := guideSection(topic); !strings.HasPrefix(s, "## ") {
			t.Errorf("guide %s: %q", topic, s)
		}
	}
	if guideSection("nosuch") != "" {
		t.Error("unknown topic should be empty")
	}
	if !strings.HasPrefix(guideSection("change"), "## 4. Change things safely") {
		t.Errorf("change: %q", guideSection("change")[:30])
	}
}

func TestPolicyCheckText(t *testing.T) {
	if got := (policyCheck{}).Text(); !strings.HasPrefix(got, "Allowed") || strings.Count(got, "\n") != 1 {
		t.Errorf("allowed: %q", got)
	}
}

func TestConnAddKindsExist(t *testing.T) {
	for k := range connAddKinds {
		c := connAddCmdFor(k)
		if c.Name() != "add" || !strings.Contains(c.Short, connAddKinds[k].what) {
			t.Errorf("%s add: %q %q", k, c.Name(), c.Short)
		}
	}
}
