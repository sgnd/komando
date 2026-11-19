package cli

import "testing"

// On Windows, filepath.Rel folds Unicode case, so this runs the real path
// functions where the lookalikes once passed as ~/.kube.
func TestInKubeDirLookalikesWindows(t *testing.T) {
	if !caseFoldFS {
		t.Fatal("Windows file systems ignore case; caseFoldFS should be set")
	}
	home := t.TempDir() + `\sam`
	for _, p := range kubeLookalikes(home) {
		if inKubeDir(p, home) {
			t.Errorf("%q should not count as ~/.kube", p)
		}
	}
}
