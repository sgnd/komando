package cli

import "testing"

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
