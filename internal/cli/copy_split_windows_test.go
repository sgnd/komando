package cli

import "testing"

// On Windows a drive letter is part of a local path, as for kubectl cp
// (C:\out.txt), not a target named C.
func TestSplitRemoteDriveLettersAreLocalWindows(t *testing.T) {
	for _, s := range []string{`C:\out.txt`, `C:out.txt`, `d:/data/out.txt`, `\\files\share\out.txt`} {
		if tgt, p, ok := splitRemote(s); ok || tgt != "" || p != s {
			t.Errorf("splitRemote(%q) = %q, %q, %v; want the whole argument as a local path", s, tgt, p, ok)
		}
	}
	if tgt, p, ok := splitRemote("web1:/srv/out.txt"); !ok || tgt != "web1" || p != "/srv/out.txt" {
		t.Errorf("a target is still a target: %q %q %v", tgt, p, ok)
	}
}
