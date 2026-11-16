package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

func TestManifestEscalates(t *testing.T) {
	pod := func(spec string) string {
		return "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n" + spec
	}
	for name, c := range map[string]struct {
		yaml string
		esc  bool
	}{
		"configmap":          {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {kind: ClusterRoleBinding, hostPID: 'yes'}\n", false},
		"plain pod":          {pod("  containers: [{name: c, image: a, securityContext: {privileged: false, capabilities: {drop: [ALL]}}}]\n"), false},
		"hostNetwork false":  {pod("  hostNetwork: false\n  containers: [{name: c, image: a}]\n"), false},
		"clusterrolebinding": {"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: a}\n", true},
		"rolebinding":        {"apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {name: a}\n", true},
		"clusterrole":        {"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: a}\n", true},
		"role":               {"apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {name: a}\n", true},
		"webhook":            {"apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingWebhookConfiguration\nmetadata: {name: a}\n", true},
		"sa token":           {"apiVersion: v1\nkind: Secret\nmetadata: {name: a, annotations: {kubernetes.io/service-account.name: admin}}\ntype: kubernetes.io/service-account-token\n", true},
		"opaque secret":      {"apiVersion: v1\nkind: Secret\nmetadata: {name: a}\ntype: Opaque\n", false},
		"hostPID":            {pod("  hostPID: true\n  containers: [{name: c, image: a}]\n"), true},
		"hostIPC":            {pod("  hostIPC: true\n  containers: [{name: c, image: a}]\n"), true},
		"hostNetwork":        {pod("  hostNetwork: true\n  containers: [{name: c, image: a}]\n"), true},
		"privileged":         {pod("  containers: [{name: c, image: a, securityContext: {privileged: true}}]\n"), true},
		"init privileged":    {pod("  containers: [{name: c, image: a}]\n  initContainers: [{name: i, image: a, securityContext: {privileged: true}}]\n"), true},
		"cap add":            {pod("  containers: [{name: c, image: a, securityContext: {capabilities: {add: [SYS_ADMIN]}}}]\n"), true},
		"hostPath":           {pod("  volumes: [{name: h, hostPath: {path: /}}]\n  containers: [{name: c, image: a}]\n"), true},
		"procMount":          {pod("  containers: [{name: c, image: a, securityContext: {procMount: Unmasked}}]\n"), true},
		"cronjob":            {"apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: a}\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          hostPID: true\n          containers: [{name: c, image: a}]\n", true},
		"list":               {"apiVersion: v1\nkind: List\nmetadata: {name: l}\nitems:\n- apiVersion: rbac.authorization.k8s.io/v1\n  kind: ClusterRoleBinding\n  metadata: {name: a}\n", true},
		"pv hostPath":        {"apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: a}\nspec:\n  hostPath: {path: /}\n", true},
		"second document":    {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n---\n" + pod("  hostPID: true\n  containers: [{name: c, image: a}]\n"), true},
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

// What was rated is what is sent: a manifest changed after the rating is
// read from the copy the command already holds.
func TestManifestReadOnce(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.yaml")
	plain := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n"
	os.WriteFile(file, []byte(plain), 0o600)
	cl := newCall(tcl.io, nil)
	if risk, why := kubectlFileRisk(cl, []string{"apply", "-f", file}, driver.RiskWrite); risk != driver.RiskWrite || why != "" {
		t.Fatalf("plain file: %v %q", risk, why)
	}
	os.WriteFile(file, []byte("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: a}\n"), 0o600)
	b, err := readManifest(cl, file, false)
	if err != nil || string(b) != plain {
		t.Errorf("the run read the file again: %q %v", b, err)
	}
	// and the other way round: a file that escalates is rated so
	cl2 := newCall(tcl.io, nil)
	if risk, why := kubectlFileRisk(cl2, []string{"create", "--filename=" + file}, driver.RiskWrite); risk != driver.RiskDestructive || why == "" {
		t.Errorf("binding file: %v %q", risk, why)
	}
	if got := classifyKubectl(tcl, []string{"create", "role", "r", "--verb=get", "--resource=pods"}); got != driver.RiskDestructive {
		t.Errorf("create role: %v", got)
	}
}

func TestComposeEscapes(t *testing.T) {
	svc := func(body string) string { return "services:\n  web:\n    image: nginx\n" + body }
	for name, c := range map[string]struct {
		yaml string
		esc  bool
	}{
		"plain":            {svc("    ports: ['80:80']\n    volumes: ['data:/var/lib/x', '/srv/site:/usr/share/nginx/html:ro']\nvolumes:\n  data: {}\n"), false},
		"localtime ro":     {svc("    volumes: ['/etc/localtime:/etc/localtime:ro']\n"), false},
		"root bind":        {svc("    volumes: ['/:/host']\n"), true},
		"docker socket":    {svc("    volumes:\n    - {type: bind, source: /var/run/docker.sock, target: /s}\n"), true},
		"etc writable":     {svc("    volumes: ['/etc:/e']\n"), true},
		"from environment": {svc("    volumes: ['${WHERE}:/h']\n"), true},
		"cap_add":          {svc("    cap_add: [SYS_ADMIN]\n"), true},
		"privileged":       {svc("    privileged: true\n"), true},
		"devices":          {svc("    devices: ['/dev/sda:/dev/sda']\n"), true},
		"pid host":         {svc("    pid: host\n"), true},
		"network_mode":     {svc("    network_mode: host\n"), true},
		"volume device":    {svc("    volumes: ['h:/h']\nvolumes:\n  h:\n    driver_opts: {type: none, o: bind, device: /}\n"), true},
		"nfs volume":       {svc("    volumes: ['n:/n']\nvolumes:\n  n:\n    driver_opts: {type: nfs, o: addr=10.0.0.9, device: ':/export'}\n"), false},
	} {
		if why := composeEscapes([]byte(c.yaml)); (why != "") != c.esc {
			t.Errorf("%s: escapes %q, want %v", name, why, c.esc)
		}
	}
}
