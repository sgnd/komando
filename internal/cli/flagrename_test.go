package cli

import (
	"strings"
	"testing"
)

// flagRenames are the C-F renames: on each command the new flag is
// visible, and each old spelling is hidden and shares its value; retired
// spellings are noted in meta.deprecated, synonyms are not.
var flagRenames = []struct {
	path     []string
	now, old string
	synonym  bool
}{
	{[]string{"db", "grant"}, "from-host", "from", false},
	{[]string{"db", "revoke"}, "from-host", "from", false},
	{[]string{"db", "user", "show"}, "from-host", "from", false},
	{[]string{"db", "grants"}, "from-host", "from", false},
	{[]string{"db", "user", "add"}, "from-host", "from", false},
	{[]string{"db", "user", "passwd"}, "from-host", "from", false},
	{[]string{"db", "user", "rm"}, "from-host", "from", false},
	{[]string{"fs", "restore"}, "copy", "from", false},
	{[]string{"cluster", "rollback"}, "revision", "to", false},
	{[]string{"cluster", "rollback"}, "revision", "to-revision", true},
	{[]string{"queue", "peek"}, "idle", "wait", false},
	{[]string{"rename"}, "starts-with", "prefix", false},
	{[]string{"rename"}, "in-notes", "notes", false},
	{[]string{"rename"}, "in-labels", "labels", false},
	{[]string{"host", "edit"}, "add-group", "group", true},
	{[]string{"host", "edit"}, "add-tag", "tag", true},
	{[]string{"conn", "edit"}, "add-group", "group", true},
	{[]string{"conn", "edit"}, "add-tag", "tag", true},
	{[]string{"vpn", "edit"}, "add-group", "group", true},
	{[]string{"vpn", "edit"}, "add-tag", "tag", true},
}

func TestStandardFlagRenames(t *testing.T) {
	root := newRoot()
	for _, r := range flagRenames {
		c := findCmd(t, root, r.path...)
		now, old := c.Flags().Lookup(r.now), c.Flags().Lookup(r.old)
		if now == nil || now.Hidden {
			t.Errorf("%v: --%s must be visible", r.path, r.now)
			continue
		}
		if old == nil || !old.Hidden || old.Value != now.Value {
			t.Errorf("%v: --%s must be a hidden spelling of --%s", r.path, r.old, r.now)
			continue
		}
		if retired := old.Annotations[flagRetired] != nil; retired == r.synonym {
			t.Errorf("%v: --%s retired=%v, want %v", r.path, r.old, retired, !r.synonym)
		}
	}
}

// docker logs has no journal priority and svc logs no --timestamps
// choice: the flags are hidden there, still accepted for one release and
// noted in meta.deprecated (C-F13).
func TestLogsIdleFlagsHidden(t *testing.T) {
	root := newRoot()
	for path, flag := range map[string]string{"docker logs": "priority", "svc logs": "timestamps"} {
		c := findCmd(t, root, strings.Fields(path)...)
		if f := c.Flags().Lookup(flag); f == nil || !f.Hidden {
			t.Errorf("%s --%s must be hidden", path, flag)
		}
	}
	if f := findCmd(t, root, "logs").Flags().Lookup("priority"); f == nil || f.Hidden {
		t.Error("logs --priority stays visible")
	}
	invHome(t)
	code, text := runMain(t, "docker", "logs", "nope", "api", "--priority", "err")
	if code == 0 || !strings.Contains(text, `"deprecated":{"used":"--priority"`) {
		t.Errorf("docker logs --priority: exit %d %s", code, text)
	}
}
