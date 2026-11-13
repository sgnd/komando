package cli

import (
	"strings"
	"testing"
)

// flagSynonyms are the flags that keep a second spelling for good (a word
// from kubectl, or the plain word for an edit): on each command the flag is
// visible, and the synonym is hidden and shares its value.
var flagSynonyms = []struct {
	path     []string
	now, old string
}{
	{[]string{"cluster", "rollback"}, "revision", "to-revision"},
	{[]string{"fs", "write"}, "content", "value"},
	{[]string{"host", "edit"}, "add-group", "group"},
	{[]string{"host", "edit"}, "add-tag", "tag"},
	{[]string{"conn", "edit"}, "add-group", "group"},
	{[]string{"conn", "edit"}, "add-tag", "tag"},
	{[]string{"vpn", "edit"}, "add-group", "group"},
	{[]string{"vpn", "edit"}, "add-tag", "tag"},
}

func TestFlagSynonyms(t *testing.T) {
	root := newRoot()
	for _, r := range flagSynonyms {
		c := findCmd(t, root, r.path...)
		now, old := c.Flags().Lookup(r.now), c.Flags().Lookup(r.old)
		if now == nil || now.Hidden {
			t.Errorf("%v: --%s must be visible", r.path, r.now)
			continue
		}
		if old == nil || !old.Hidden || old.Value != now.Value {
			t.Errorf("%v: --%s must be a hidden spelling of --%s", r.path, r.old, r.now)
		}
	}
}

// docker logs has no journal priority and svc logs no --timestamps
// choice: those flags are not there (C-F13); logs keeps both.
func TestLogsIdleFlagsGone(t *testing.T) {
	root := newRoot()
	for path, flag := range map[string]string{"docker logs": "priority", "svc logs": "timestamps"} {
		if f := findCmd(t, root, strings.Fields(path)...).Flags().Lookup(flag); f != nil {
			t.Errorf("%s has --%s", path, flag)
		}
	}
	for _, flag := range []string{"priority", "timestamps"} {
		if f := findCmd(t, root, "logs").Flags().Lookup(flag); f == nil || f.Hidden {
			t.Errorf("logs --%s stays visible", flag)
		}
	}
}

// cron reads root's crontab with --user root; it has no --sudo (C-F19).
func TestCronUserRoot(t *testing.T) {
	root := newRoot()
	if f := findCmd(t, root, "cron", "list").InheritedFlags().Lookup("sudo"); f != nil {
		t.Errorf("cron has --sudo: %+v", f)
	}
	if f := findCmd(t, root, "cron", "list").InheritedFlags().Lookup("user"); f == nil || f.Hidden {
		t.Error("cron --user stays visible")
	}
}
