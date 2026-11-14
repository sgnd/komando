package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// kubeconfigAt writes a one-context kubeconfig (context prod) for server.
func kubeconfigAt(t *testing.T, server string) string {
	t.Helper()
	kc := "current-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: " + server +
		"\nusers:\n- name: prod\n  user:\n    token: test-token\ncontexts:\n- name: prod\n  context: {cluster: prod, user: prod, namespace: shop}\n"
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

// --timeout ends a cluster that does not answer, for every command, not
// only cluster run.
func TestClusterTimeout(t *testing.T) {
	invHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(func() { srv.CloseClientConnections(); srv.Close() })
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, srv.URL))
	for _, args := range [][]string{{"status", "prod"}, {"ls", "prod", "pods"}, {"events", "prod"}, {"get", "prod", "pod", "x"}} {
		start := time.Now()
		_, e := invRun(t, append([]string{"--timeout", "300ms", "cluster"}, args...)...)
		if e == nil || e.Code != "TIMEOUT" || e.Exit != out.ExitTimeout {
			t.Errorf("%v: %+v", args, e)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%v took %s", args, d)
		}
	}
}

// A refused connection reads as `komando test` says it, not as Go's words.
func TestKubeErrWords(t *testing.T) {
	addr := closedAddr(t)
	_, err := http.Get("http://" + addr + "/")
	e := toErr(kubeErr(err))
	if e.Code != "K8S_UNREACHABLE" || e.Message != "cannot reach "+addr+": connection refused" {
		t.Errorf("refused: %+v", e)
	}
	if e := toErr(kubeErr(fmt.Errorf("x: %w", context.DeadlineExceeded))); e.Code != "TIMEOUT" {
		t.Errorf("deadline: %+v", e)
	}
}

// An unreachable cluster is K8S_UNREACHABLE in cluster run and apply too,
// not "no resource type" (exit 5) or a usage error (exit 2).
func TestClusterUnreachableIsUnreachable(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	for _, args := range [][]string{{"run", "prod", "--", "get", "pods"}, {"run", "prod", "--", "version"}} {
		if _, e := invRun(t, append([]string{"cluster"}, args...)...); e == nil || e.Code != "K8S_UNREACHABLE" || e.Exit != out.ExitConnect {
			t.Errorf("%v: %+v", args, e)
		}
	}
	f := filepath.Join(t.TempDir(), "cm.yaml")
	os.WriteFile(f, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"), 0o600)
	if _, e := invRun(t, "cluster", "apply", "prod", "--file", f); e == nil || e.Code != "K8S_UNREACHABLE" {
		t.Errorf("apply: %+v", e)
	}
}

// A change whose connection breaks after the request went out may have
// happened: it is K8S_UNREACHABLE and still lands in the audit log.
func TestClusterRunBrokenWriteIsAudited(t *testing.T) {
	invHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1":
			w.Write([]byte(`{"resources":[{"name":"configmaps","kind":"ConfigMap","namespaced":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/apis":
			w.Write([]byte(`{"groups":[]}`))
		default:
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}
	}))
	t.Cleanup(srv.Close)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, srv.URL))
	if _, e := invRun(t, "cluster", "run", "prod", "--write", "--", "create", "configmap", "x"); e == nil || e.Code != "K8S_UNREACHABLE" {
		t.Fatalf("run: %+v", e)
	}
	d := mustRun(t, "audit", "--failed")
	if b, _ := json.Marshal(d); !strings.Contains(string(b), "kubectl create configmap x") {
		t.Errorf("the broken write is not in the audit log: %s", b)
	}
}

// What komando's kubectl never runs is a usage error first, not "needs --write".
func TestClusterRunUsageFirst(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	for _, c := range []struct{ args, want string }{
		{"gte pods", `unknown command "gte" for komando's kubectl; did you mean "get"?`},
		{"config view", "config supports current-context and get-contexts"},
		{"port-forward svc/x 80", "is a session"},
	} {
		e := wantCode(t, "USAGE", append([]string{"cluster", "run", "prod", "--"}, strings.Fields(c.args)...)...)
		if !strings.Contains(e.Message, c.want) {
			t.Errorf("%s: %q", c.args, e.Message)
		}
	}
	e := toErr(execInstead(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "re-run with --allow-dangerous", "x"), "exec"))
	if !strings.Contains(e.Hint, "komando cluster exec") || !strings.Contains(e.Hint, "--allow-dangerous") {
		t.Errorf("exec hint: %q", e.Hint)
	}
}

// Only the API's NotFound is K8S_NOT_FOUND; a command in a pod that is
// not found is the command's own failure.
func TestKubectlFailureNotFoundOnlyFromAPI(t *testing.T) {
	if f := kubectlFailure(127, "sh: foo: not found\ncommand terminated with exit code 127\n"); f.Code != "FAILED" {
		t.Errorf("exec: %+v", f)
	}
}

// statusLab serves a cluster with a short StatefulSet and DaemonSet, and
// refuses to list nodes, like a namespace-only account.
func statusLab(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		item := func(kind string, spec, status map[string]any) {
			json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"kind": kind,
				"metadata": map[string]any{"name": "db", "namespace": "shop"}, "spec": spec, "status": status}}})
		}
		switch p := r.URL.Path; {
		case p == "/version":
			io.WriteString(w, `{"gitVersion":"v1.31.0"}`)
		case p == "/api/v1/nodes":
			w.WriteHeader(403)
			io.WriteString(w, `{"reason":"Forbidden","message":"nodes is forbidden"}`)
		case strings.HasSuffix(p, "/statefulsets"):
			item("StatefulSet", map[string]any{"replicas": 3}, map[string]any{"readyReplicas": 0})
		case strings.HasSuffix(p, "/daemonsets"):
			item("DaemonSet", nil, map[string]any{"desiredNumberScheduled": 4, "numberReady": 3})
		case strings.HasSuffix(p, "/pods"):
			if r.URL.Query().Get("continue") == "" {
				io.WriteString(w, `{"metadata":{"continue":"next"},"items":[]}`)
				return
			}
			io.WriteString(w, `{"items":[{"metadata":{"name":"p","namespace":"shop"},"status":{"phase":"Pending"}}]}`)
		default:
			io.WriteString(w, `{"items":[]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// cluster status counts StatefulSets and DaemonSets, reads every page,
// and still answers for an account that may not list nodes.
func TestClusterStatusWorkloads(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, statusLab(t)))
	d := mustRun(t, "cluster", "status", "prod", "--namespace", "shop")
	b, _ := json.Marshal(d)
	for _, want := range []string{`statefulset/shop/db","problem":"0 of 3 replicas ready"`, `daemonset/shop/db","problem":"3 of 4 pods ready"`,
		`pod/shop/p","problem":"pending"`, `this account may not list them`, `"healthy":false`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("want %s in %s", want, b)
		}
	}
}

// A context that cannot be imported keeps its name: a context whose name
// differs only in case does not get it and point the name elsewhere.
// Relative certificate paths count from the kubeconfig's folder.
func TestImportKubeconfigNames(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("CA"), 0o600)
	kc := `clusters:
- name: c1
  cluster: {server: "https://127.0.0.1:6449", certificate-authority: missing.crt}
- name: c2
  cluster: {server: "https://127.0.0.1:6450", certificate-authority: ca.crt}
users:
- name: u
  user: {token: t}
contexts:
- name: prod
  context: {cluster: c1, user: u}
- name: Prod
  context: {cluster: c2, user: u}
`
	p := filepath.Join(dir, "b.yaml")
	os.WriteFile(p, []byte(kc), 0o600)
	t.Chdir(t.TempDir())
	d := mustRun(t, "import", "kubeconfig", p)
	b, _ := json.Marshal(d)
	if fmt.Sprint(d["conns"]) != "[prod-2]" || !strings.Contains(string(b), "context prod: open ") ||
		!strings.Contains(string(b), "contexts prod and Prod both make the conn name prod; context Prod is the conn prod-2") {
		t.Errorf("import: %s", b)
	}
	if _, e := invRun(t, "conn", "show", "prod"); e == nil {
		t.Error("no conn may be called prod: its context was not imported")
	}
}

// With no file named, import kubeconfig reads $KUBECONFIG, as kubectl does.
func TestImportKubeconfigEnv(t *testing.T) {
	invHome(t)
	// kubectl leaves out a file of the list that does not exist, and empty entries
	sep := string(os.PathListSeparator)
	t.Setenv("KUBECONFIG", kubeconfigAt(t, "https://127.0.0.1:6449")+sep+sep+filepath.Join(t.TempDir(), "none"))
	if d := mustRun(t, "import", "kubeconfig", "--dry-run"); fmt.Sprint(d["conns"]) != "[prod]" {
		t.Errorf("a missing file in the list: %v", d)
	}
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "none")+sep+filepath.Join(t.TempDir(), "none2"))
	if _, e := invRun(t, "import", "kubeconfig", "--dry-run"); e == nil || e.Code != "FILE_NOT_FOUND" {
		t.Errorf("no file of the list exists: %+v", e)
	}
	t.Setenv("KUBECONFIG", kubeconfigAt(t, "https://127.0.0.1:6449"))
	if d := mustRun(t, "import", "kubeconfig", "--dry-run"); fmt.Sprint(d["conns"]) != "[prod]" {
		t.Errorf("KUBECONFIG: %v", d)
	}
}

// An imported login program is a note about the added conn, not "not imported".
func TestImportKubeconfigPluginNote(t *testing.T) {
	invHome(t)
	noAgent(t)
	kc := "clusters:\n- name: c\n  cluster: {server: \"https://127.0.0.1:6449\"}\nusers:\n- name: u\n  user:\n    exec: {command: /usr/bin/true, args: [x]}\ncontexts:\n- name: ex\n  context: {cluster: c, user: u}\n"
	p := filepath.Join(t.TempDir(), "ex.yaml")
	os.WriteFile(p, []byte(kc), 0o600)
	d := mustRun(t, "import", "kubeconfig", p, "--dry-run")
	if fmt.Sprint(d["not_imported"]) != "[]" || !strings.Contains(fmt.Sprint(d["notes"]), "/usr/bin/true x") {
		t.Errorf("plugin note: %v", d)
	}
}

// cluster add takes only a cluster URL, and a k8s one only with its kubeconfig.
func TestClusterAddKind(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "cluster", "add", "k1", "k8s://127.0.0.1:6451")
	wantCode(t, "WRONG_KIND", "cluster", "add", "r1", "registry://ghcr.io")
	wantCode(t, "WRONG_KIND", "registry", "add", "k3", "k8s://1.2.3.4")
	if e := wantCode(t, "USAGE", "cluster", "add", "sw1", "ssh://deploy@10.0.0.9"); !strings.Contains(e.Hint, "host add") {
		t.Errorf("swarm: %+v", e)
	}
	mustRun(t, "cluster", "add", "k2", "k8s://127.0.0.1:6451", "--password-ref", "secret:k2-kubeconfig")
}

// all and @group read a server as a Swarm manager only when it is tagged
// swarm or named; other servers are skipped, not failed.
func TestClusterSelectorSkipsPlainServers(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, statusLab(t)))
	mustRun(t, "host", "add", "web1", "deploy@192.0.2.20")
	mustRun(t, "host", "add", "sw1", "deploy@192.0.2.21", "--tag", "swarm")
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	ts, err := resolveClusters(tcl, st, "all")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range ts {
		names = append(names, x.name())
	}
	if strings.Join(names, ",") != "prod,sw1" {
		t.Errorf("all: %v", names)
	}
	if ts, err := resolveClusters(tcl, st, "prod,web1"); err != nil || len(ts) != 2 {
		t.Errorf("a named server counts: %v %v", ts, err)
	}
	if ts, err := resolveClusters(tcl, st, "web1"); err != nil || len(ts) != 1 {
		t.Errorf("one server alone counts: %v %v", ts, err)
	}
}

// Flags that cannot be right are refused before komando connects.
func TestClusterFlagChecks(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	if _, e := invRun(t, "cluster", "ls", "prod", "pods", "--namespace", "shop", "-A"); e == nil || e.Exit != out.ExitUsage {
		t.Errorf("--namespace with -A: %+v", e)
	}
	wantCode(t, "USAGE", "cluster", "helm", "values", "prod", "x", "--revision", "-2")
}
