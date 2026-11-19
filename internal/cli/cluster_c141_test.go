package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// kustomize output is never read, so -k is refused before anything runs.
func TestKubectlKustomizeRefused(t *testing.T) {
	for _, args := range [][]string{{"apply", "-k", "dir"}, {"apply", "--kustomize=dir"}, {"delete", "-k", "dir"}} {
		if err := checkKubectlFlags(args); err == nil || !strings.Contains(err.Error(), "kustomize") {
			t.Errorf("%v: want a kustomize refusal, got %v", args, err)
		}
	}
}

// Only ASCII is folded when a credential store is let through as ~/.kube.
func TestInKubeDirASCIIFold(t *testing.T) {
	saved := caseFoldFS
	caseFoldFS = true // as on macOS and Windows; the Linux CI runs it too
	t.Cleanup(func() { caseFoldFS = saved })
	home := filepath.Join(t.TempDir(), "sam")
	if !inKubeDir(filepath.Join(home, ".KUBE", "config"), home) {
		t.Error("~/.KUBE/config should be in ~/.kube")
	}
	for _, p := range kubeLookalikes(home) {
		if inKubeDir(p, home) {
			t.Errorf("%q should not count as ~/.kube", p)
		}
	}
}

// kubeLookalikes are paths whose letters fold to ~/.kube only under Unicode
// case folding: the Kelvin sign (U+212A) folds to k, the long s (U+017F) to s.
func kubeLookalikes(home string) []string {
	dir, base := filepath.Split(home)
	return []string{
		filepath.Join(home, ".\u212Aube", "config"),
		filepath.Join(dir+strings.Replace(base, "s", "\u017F", 1), ".kube", "config"),
	}
}
