package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Manifests that give out rights or open a node need --allow-dangerous,
// like `cluster run -- create clusterrolebinding` and `-- run
// --privileged` do; before, a file took them to the cluster as a plain
// write. Nothing reaches the cluster without the approval.
func TestManifestTier(t *testing.T) {
	invHome(t)
	l := newApplyLab(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, "    token: test-token-abcdef"))
	dir := t.TempDir()
	files := map[string]string{
		"binding": "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: pwn}\nroleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\nsubjects: [{kind: ServiceAccount, name: default, namespace: shop}]\n",
		"pod":     "apiVersion: v1\nkind: Pod\nmetadata: {name: esc}\nspec:\n  hostPID: true\n  containers: [{name: c, image: alpine}]\n",
		"deploy":  "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: esc}\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        image: alpine\n        securityContext: {privileged: true}\n",
		"mixed":   "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: fine}\ndata: {a: b}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: esc}\nspec:\n  volumes: [{name: h, hostPath: {path: /}}]\n  containers: [{name: c, image: alpine}]\n",
	}
	for name, body := range files {
		file := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"cluster", "apply", "prod", "--file", file},
			{"cluster", "run", "prod", "--write", "--", "apply", "-f", file},
			{"cluster", "run", "prod", "--write", "--", "create", "-f", file},
		} {
			_, e := cliRun(t, args...)
			if e == nil || e.Code != "POLICY_BLOCKED" {
				t.Errorf("%s %v: want POLICY_BLOCKED, got %+v", name, args[1:4], e)
			}
		}
	}
	if len(l.real)+len(l.dry) != 0 {
		t.Errorf("sent to the cluster without the approval: real %v, dry %v", l.real, l.dry)
	}
	// a dry run is not stopped, and says what the real run needs
	d, e := cliRun(t, "--dry-run", "cluster", "apply", "prod", "--file", filepath.Join(dir, "pod.yaml"))
	if e != nil {
		t.Fatalf("dry run: %+v (%v)", e, d)
	}
	// an ordinary file is still a plain change
	file := filepath.Join(dir, "cm.yaml")
	os.WriteFile(file, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: plain}\ndata: {a: b}\n"), 0o600)
	if _, e := cliRun(t, "cluster", "apply", "prod", "--file", file); e != nil {
		t.Fatalf("a ConfigMap: %+v", e)
	}
	if _, e := cliRun(t, "cluster", "run", "prod", "--write", "--", "apply", "-f", file); e != nil {
		t.Fatalf("a ConfigMap through cluster run: %+v", e)
	}
	if got := strings.Join(l.real, ","); got != "plain,plain" {
		t.Errorf("applied for real: %q", got)
	}
}
