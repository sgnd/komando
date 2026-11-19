package cli

import (
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
	if !caseFoldFS {
		t.Skip("case is only folded where the file system ignores it")
	}
	home := t.TempDir()
	if !inKubeDir(home+"/.KUBE/config", home) {
		t.Error("~/.KUBE/config should be in ~/.kube")
	}
	if inKubeDir(home+"/.Kube/config", home) {
		t.Error("~/.Kube (Kelvin sign) should not be in ~/.kube")
	}
}
