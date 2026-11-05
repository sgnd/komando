package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/kube"
)

func TestParseKargs(t *testing.T) {
	a, err := parseKargs([]string{"get", "pods", "-n", "shop", "-oyaml", "-lapp=web", "--field-selector=status.phase=Running", "-A", "--", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if a.verb != "get" || a.pos[0] != "pods" || a.val("namespace") != "shop" || a.val("output") != "yaml" || a.val("selector") != "app=web" ||
		a.val("field-selector") != "status.phase=Running" || !a.bools["all-namespaces"] || a.rest[0] != "x" {
		t.Errorf("parsed %+v", a)
	}
	a, _ = parseKargs([]string{"logs", "deploy/api", "-f", "-p", "--tail", "5"})
	if !a.bools["follow"] || !a.bools["previous"] || a.val("tail") != "5" {
		t.Errorf("logs flags %+v", a)
	}
	a, _ = parseKargs([]string{"apply", "-f", "app.yaml"})
	if a.vals["filename"][0] != "app.yaml" {
		t.Errorf("-f is a file outside logs: %+v", a)
	}
	if _, err := parseKargs([]string{"get", "pods", "--kubeconfig", "/x"}); err == nil {
		t.Error("unknown flags are refused")
	}
	if _, err := parseKargs([]string{"get", "pods", "-n"}); err == nil {
		t.Error("a value flag without a value is refused")
	}
}

func TestKubectlTable(t *testing.T) {
	got := kubectlTable([]string{"NAME", "READY"}, [][]string{{"web-1", "1/1"}, {"a", "0/1"}}, false)
	want := "NAME    READY\nweb-1   1/1\na       0/1\n"
	if got != want {
		t.Errorf("table:\n%q\nwant\n%q", got, want)
	}
}

// fakeAPI serves discovery, one deployment, tables and the writes kctl
// makes, recording them.
type fakeAPI struct {
	mu     sync.Mutex
	writes []string
}

func (f *fakeAPI) client(t *testing.T) *kube.Client {
	t.Helper()
	deploy := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "shop", "labels": map[string]any{"app": "web"}, "resourceVersion": "7"},
		"spec":     map[string]any{"replicas": 2}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" {
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.writes = append(f.writes, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type")+" "+r.URL.Query().Get("dryRun")+" "+string(b))
			f.mu.Unlock()
		}
		switch {
		case r.URL.Path == "/api/v1":
			io.WriteString(w, `{"resources":[{"name":"pods","kind":"Pod","namespaced":true,"shortNames":["po"]},{"name":"configmaps","kind":"ConfigMap","namespaced":true,"shortNames":["cm"]},{"name":"nodes","kind":"Node","namespaced":false}]}`)
		case r.URL.Path == "/apis":
			io.WriteString(w, `{"groups":[{"preferredVersion":{"groupVersion":"apps/v1"}},{"preferredVersion":{"groupVersion":"authorization.k8s.io/v1"}}]}`)
		case r.URL.Path == "/apis/apps/v1":
			io.WriteString(w, `{"resources":[{"name":"deployments","kind":"Deployment","namespaced":true,"shortNames":["deploy"]}]}`)
		case r.URL.Path == "/apis/authorization.k8s.io/v1":
			io.WriteString(w, `{"resources":[{"name":"selfsubjectaccessreviews","kind":"SelfSubjectAccessReview","namespaced":false}]}`)
		case strings.Contains(r.Header.Get("Accept"), "as=Table") && r.URL.Path == "/apis/apps/v1/namespaces/shop/deployments":
			io.WriteString(w, `{"columnDefinitions":[{"name":"Name","priority":0},{"name":"Ready","priority":0},{"name":"Images","priority":1}],
				"rows":[{"cells":["web","2/2","nginx"],"object":{"metadata":{"name":"web","namespace":"shop"}}}]}`)
		case strings.Contains(r.Header.Get("Accept"), "as=Table") && r.URL.Path == "/apis/apps/v1/deployments":
			io.WriteString(w, `{"columnDefinitions":[{"name":"Name","priority":0}],"rows":[{"cells":["web"],"object":{"metadata":{"name":"web","namespace":"shop"}}}]}`)
		case strings.Contains(r.Header.Get("Accept"), "as=Table") && r.URL.Path == "/api/v1/namespaces/shop/pods":
			io.WriteString(w, `{"columnDefinitions":[{"name":"Name","priority":0}],"rows":[]}`)
		case r.URL.Path == "/apis/apps/v1/namespaces/shop/deployments" && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"items": []any{deploy}})
		case r.URL.Path == "/apis/apps/v1/namespaces/shop/deployments/web" && r.Method == "GET":
			json.NewEncoder(w).Encode(deploy)
		case r.URL.Path == "/apis/apps/v1/namespaces/shop/deployments/nope":
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","message":"not there"}`)
		case r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			b := strings.Join(f.writes, "")
			io.WriteString(w, `{"status":{"allowed":`+map[bool]string{true: "true", false: "false"}[strings.Contains(b, `"verb":"get"`)]+`}}`)
		default:
			if r.Method != "GET" {
				io.WriteString(w, `{}`)
				return
			}
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","message":"`+r.URL.Path+`"}`)
		}
	}))
	t.Cleanup(srv.Close)
	x := &kube.Context{Namespace: "shop"}
	x.Cluster.Server = srv.URL
	k, err := kube.New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKctlRead(t *testing.T) {
	f := &fakeAPI{}
	k := f.client(t)
	run := func(args ...string) (int, string, string) { return runKctl(context.Background(), k, "lab", args) }

	if code, so, _ := run("get", "deploy"); code != 0 || so != "NAME   READY\nweb    2/2\n" {
		t.Errorf("table: %d %q", code, so)
	}
	if _, so, _ := run("get", "deployments", "-o", "wide"); !strings.Contains(so, "IMAGES") || !strings.Contains(so, "nginx") {
		t.Errorf("wide: %q", so)
	}
	if _, so, _ := run("get", "deploy", "-A"); !strings.HasPrefix(so, "NAMESPACE   NAME\nshop        web") {
		t.Errorf("all namespaces: %q", so)
	}
	if _, so, _ := run("get", "deploy", "web", "-o", "name"); so != "deployment.apps/web\n" {
		t.Errorf("name: %q", so)
	}
	if _, so, _ := run("get", "deploy/web", "-o", "jsonpath={.spec.replicas}"); so != "2" {
		t.Errorf("jsonpath: %q", so)
	}
	if _, so, _ := run("get", "deploy", "-o", "custom-columns=N:.metadata.name,R:.spec.replicas"); so != "N     R\nweb   2\n" {
		t.Errorf("custom-columns: %q", so)
	}
	if _, so, _ := run("get", "deploy", "web", "-o", "json"); !strings.Contains(so, `"kind": "Deployment"`) {
		t.Errorf("json: %q", so)
	}
	if _, so, _ := run("get", "deploy", "web", "-o", "yaml"); !strings.Contains(so, "kind: Deployment") {
		t.Errorf("yaml: %q", so)
	}
	if code, _, se := run("get", "pods"); code != 0 || se != "No resources found in shop namespace.\n" {
		t.Errorf("empty: %d %q", code, se)
	}
	if code, _, se := run("get", "deploy", "nope"); code != 1 || !strings.Contains(se, `Error from server (NotFound): deployments.apps "nope" not found`) {
		t.Errorf("not found: %d %q", code, se)
	}
	if code, _, se := run("get", "widgets"); code != 1 || !strings.Contains(se, `doesn't have a resource type "widgets"`) {
		t.Errorf("unknown type: %d %q", code, se)
	}
	if code, so, _ := run("auth", "can-i", "get", "pods"); code != 0 || so != "yes\n" {
		t.Errorf("can-i yes: %d %q", code, so)
	}
	if code, _, se := run("frobnicate"); code != 1 || !strings.Contains(se, "unknown command") {
		t.Errorf("unknown verb: %d %q", code, se)
	}
	if code, _, se := run("port-forward", "x"); code != 1 || !strings.Contains(se, "komando cluster forward") {
		t.Errorf("sessions point at komando's own commands: %d %q", code, se)
	}
}

func TestKctlWrite(t *testing.T) {
	f := &fakeAPI{}
	k := f.client(t)
	run := func(args ...string) (int, string, string) { return runKctl(context.Background(), k, "lab", args) }
	checks := []struct {
		args  []string
		out   string
		write string
	}{
		{[]string{"scale", "deploy/web", "--replicas=3"}, "deployment.apps/web scaled\n", `PATCH /apis/apps/v1/namespaces/shop/deployments/web/scale application/merge-patch+json  {"spec":{"replicas":3}}`},
		{[]string{"label", "deploy", "web", "tier=front", "old-"}, "deployment.apps/web labeled\n", `{"metadata":{"labels":{"old":null,"tier":"front"}}}`},
		{[]string{"create", "configmap", "cfg", "--from-literal=a=1"}, "configmap/cfg created\n", `"data":{"a":"1"}`},
		{[]string{"patch", "deploy", "web", "--type", "merge", "-p", "spec: {replicas: 1}"}, "deployment.apps/web patched\n", `{"spec":{"replicas":1}}`},
		{[]string{"set", "image", "deploy/web", "web=nginx:2"}, "deployment.apps/web image updated\n", `"image":"nginx:2"`},
		{[]string{"rollout", "restart", "deploy/web"}, "deployment.apps/web restarted\n", "kubectl.kubernetes.io/restartedAt"},
		{[]string{"cordon", "node1"}, "node/node1 cordoned\n", `{"spec":{"unschedulable":true}}`},
		{[]string{"delete", "deploy", "web", "--wait=false"}, "deployment.apps \"web\" deleted from shop namespace\n", "DELETE /apis/apps/v1/namespaces/shop/deployments/web"},
	}
	for _, c := range checks {
		f.writes = nil
		code, so, se := run(c.args...)
		if code != 0 || so != c.out {
			t.Errorf("%v: %d %q %q", c.args, code, so, se)
			continue
		}
		if all := strings.Join(f.writes, "\n"); !strings.Contains(all, c.write) {
			t.Errorf("%v sent %s\nwant %s", c.args, all, c.write)
		}
	}
	// label refuses to change a value without --overwrite
	if code, _, se := run("label", "deploy", "web", "app=other"); code != 1 || !strings.Contains(se, "--overwrite is false") {
		t.Errorf("overwrite: %d %q", code, se)
	}
	// --dry-run reaches the server as dryRun=All
	saved := g.dryRun
	g.dryRun = true
	f.writes = nil
	_, so, _ := run("scale", "deploy/web", "--replicas=0")
	g.dryRun = saved
	if !strings.Contains(so, "(server dry run)") || !strings.Contains(strings.Join(f.writes, ""), " All ") {
		t.Errorf("dry run: %q %v", so, f.writes)
	}
}

func TestQuantities(t *testing.T) {
	if milliCPU("250m") != 250 || milliCPU("2") != 2000 || milliCPU("1500000n") != 1 {
		t.Error("cpu")
	}
	if bytesOf("128Mi") != 128<<20 || bytesOf("1Gi") != 1<<30 || bytesOf("1000") != 1000 {
		t.Error("memory")
	}
}
