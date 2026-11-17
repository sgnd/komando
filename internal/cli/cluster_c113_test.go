package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// C113 (b): manifests that hand out rights through a controller, a
// cluster's own service accounts or EKS's user map need
// --allow-dangerous, as RBAC objects do.
func TestManifestEscalatesC113(t *testing.T) {
	for name, c := range map[string]struct {
		yaml string
		esc  bool
	}{
		"k3s HelmChart":       {"apiVersion: helm.cattle.io/v1\nkind: HelmChart\nmetadata: {name: a, namespace: kube-system}\nspec: {chart: x}\n", true},
		"argo Application":    {"apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata: {name: a}\nspec: {}\n", true},
		"argo ApplicationSet": {"apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata: {name: a}\n", true},
		"argo AppProject":     {"apiVersion: argoproj.io/v1alpha1\nkind: AppProject\nmetadata: {name: a}\n", true},
		"flux Kustomization":  {"apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata: {name: a}\n", true},
		"flux HelmRelease":    {"apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata: {name: a}\n", true},
		"other Application":   {"apiVersion: app.k8s.io/v1beta1\nkind: Application\nmetadata: {name: a}\n", false},
		"kustomize file kind": {"apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nmetadata: {name: a}\n", false},
		"aws-auth":            {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: aws-auth, namespace: kube-system}\ndata: {mapRoles: x}\n", true},
		"aws-auth elsewhere":  {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: aws-auth, namespace: shop}\n", false},
		"kube-system SA pod":  {"apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a, namespace: kube-system}\nspec:\n  template:\n    spec:\n      serviceAccountName: clusterrole-aggregation-controller\n      containers: [{name: c, image: a}]\n", true},
		"app SA pod":          {"apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: a, namespace: shop}\nspec:\n  template:\n    spec:\n      serviceAccountName: shop-api\n      containers: [{name: c, image: a}]\n", false},
	} {
		docs, err := splitYAML([]byte(c.yaml))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if why := manifestEscalates(docs); (why != "") != c.esc {
			t.Errorf("%s: escalates %q, want %v", name, why, c.esc)
		}
	}
}

// The same through `cluster run`: a namespace label that lets privileged
// pods run (or takes the rule away), and a workload moved to another
// service account.
func TestClassifyKubectlC113(t *testing.T) {
	for cmd, want := range map[string]driver.Risk{
		"label ns shop pod-security.kubernetes.io/enforce=privileged":                    driver.RiskDestructive,
		"label namespace shop pod-security.kubernetes.io/enforce=privileged --overwrite": driver.RiskDestructive,
		"label ns shop pod-security.kubernetes.io/enforce-":                              driver.RiskDestructive,
		"label ns shop pod-security.kubernetes.io/enforce=restricted":                    driver.RiskWrite,
		"label pod p tier=web":                driver.RiskWrite,
		"set serviceaccount deploy/api admin": driver.RiskDestructive,
		"set sa deploy/api admin":             driver.RiskDestructive,
	} {
		if got := classifyKubectl(tcl, strings.Fields(cmd)); got != want {
			t.Errorf("%s: %v, want %v", cmd, got, want)
		}
	}
}
