package cli

import (
	"context"
	"encoding/json"
	"fmt"
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

// --timeout ends a cluster that does not answer.
func TestClusterTimeout(t *testing.T) {
	invHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(func() { srv.CloseClientConnections(); srv.Close() })
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, srv.URL))
	for _, args := range [][]string{{"kubernetes", "raw", "prod", "--", "get", "pods"}, {"kubernetes", "raw", "prod", "--", "get", "events"}, {"kubernetes", "raw", "prod", "--", "get", "pod", "x"}, {"kubernetes", "raw", "prod", "--", "version"}} {
		start := time.Now()
		_, e := invRun(t, append([]string{"--timeout", "300ms", "cluster"}, args...)...)
		// raw reports kubectl's own failure (TOOL_FAILED, "timed out"), not TIMEOUT: found when D4 removed the typed commands (row C496)
		if e == nil || !strings.Contains(e.Message, "timed out") {
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
	if e.Code != "CONN_UNREACHABLE" || e.Message != "cannot reach "+addr+": connection refused" {
		t.Errorf("refused: %+v", e)
	}
	if e := toErr(kubeErr(fmt.Errorf("x: %w", context.DeadlineExceeded))); e.Code != "TIMEOUT" {
		t.Errorf("deadline: %+v", e)
	}
}

// An unreachable cluster is CONN_UNREACHABLE in cluster kubernetes raw,
// not "no resource type" (exit 5) or a usage error (exit 2).
func TestClusterUnreachableIsUnreachable(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	for _, args := range [][]string{{"raw", "prod", "--", "get", "pods"}, {"raw", "prod", "--", "version"}} {
		if _, e := invRun(t, append([]string{"cluster", "kubernetes"}, args...)...); e == nil || e.Code != "CONN_UNREACHABLE" || e.Exit != out.ExitConnect {
			t.Errorf("%v: %+v", args, e)
		}
	}
}

// A change whose connection breaks after the request went out may have
// happened: it is CONN_UNREACHABLE and still lands in the audit log.
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
	if _, e := invRun(t, "cluster", "kubernetes", "raw", "prod", "--write", "--", "create", "configmap", "x"); e == nil || e.Code != "CONN_UNREACHABLE" {
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
		{"gte pods", `"gte" is not a command of komando's kubectl; did you mean "get"?`},
		{"config view", "config supports current-context and get-contexts"},
		{"port-forward svc/x 80", "is a session"},
	} {
		e := wantCode(t, "USAGE", append([]string{"cluster", "kubernetes", "raw", "prod", "--"}, strings.Fields(c.args)...)...)
		if !strings.Contains(e.Message, c.want) {
			t.Errorf("%s: %q", c.args, e.Message)
		}
	}
	e := toErr(execInstead(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "re-run with --allow-dangerous", "x"), "exec"))
	if !strings.Contains(e.Hint, "komando cluster kubernetes exec") || !strings.Contains(e.Hint, "--allow-dangerous") {
		t.Errorf("exec hint: %q", e.Hint)
	}
}

// Only the API's NotFound is K8S_NOT_FOUND; a command in a pod that is
// not found is the command's own failure: kubectl, a program komando
// ran, failed (TOOL_FAILED).
func TestKubectlFailureNotFoundOnlyFromAPI(t *testing.T) {
	if f := kubectlFailure(127, "sh: foo: not found\ncommand terminated with exit code 127\n"); f.Code != "TOOL_FAILED" || f.Exit != out.ExitRemote {
		t.Errorf("exec: %+v", f)
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

// cluster kubernetes add takes only a cluster URL, and a k8s one only with its kubeconfig.
func TestClusterAddKind(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "cluster", "kubernetes", "add", "k1", "k8s://127.0.0.1:6451")
	wantCode(t, "WRONG_KIND", "cluster", "kubernetes", "add", "r1", "registry://ghcr.io")
	wantCode(t, "WRONG_KIND", "registry", "oci", "add", "k3", "k8s://1.2.3.4")
	if e := wantCode(t, "USAGE", "cluster", "kubernetes", "add", "sw1", "ssh://deploy@10.0.0.9"); !strings.Contains(e.Hint, "host add") {
		t.Errorf("swarm: %+v", e)
	}
	saveSecrets(t, "k2-kubeconfig")
	mustRun(t, "cluster", "kubernetes", "add", "k2", "k8s://127.0.0.1:6451", "--credential", "k2-kubeconfig")
}

// `cluster swarm raw` takes a manager server: a Kubernetes entry is WRONG_KIND
// with its own path, and a destructive docker verb is stopped before komando
// connects (swarm is rated by the docker rules, not the kubectl ones).
func TestClusterSwarmRawManager(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	mustRun(t, "host", "add", "sw1", "deploy@192.0.2.21", "--tag", "swarm")
	e := wantCode(t, "WRONG_KIND", "cluster", "swarm", "raw", "prod", "--", "service", "ls")
	if !strings.Contains(e.Hint, "komando cluster kubernetes raw prod") {
		t.Errorf("WRONG_KIND hint: %q", e.Hint)
	}
	if _, e := cliRun(t, "cluster", "swarm", "raw", "sw1", "--write", "--", "service", "rm", "web"); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Errorf("service rm on a manager: %+v", e)
	}
}

// A selector that picks an entry of another provider is WRONG_KIND, as its
// name is: a group holding a cache, and a label on it.
func TestClusterKubernetesSelectorsCheckProvider(t *testing.T) {
	invHome(t)
	mustRun(t, "import", "kubeconfig", kubeconfigAt(t, "https://"+closedAddr(t)))
	mustRun(t, "cache", "redis", "add", "r1", "redis://127.0.0.1:6379")
	mustRun(t, "conn", "edit", "r1", "--add-group", "mixed", "--label", "tier=db")
	mustRun(t, "conn", "edit", "prod", "--add-group", "mixed")
	for _, args := range [][]string{
		{"cluster", "kubernetes", "test", "r1"}, {"cluster", "kubernetes", "test", "@mixed"}, {"cluster", "kubernetes", "test", "label:tier=db"},
		{"cluster", "kubernetes", "remove", "@mixed"}, {"cluster", "kubernetes", "remove", "label:tier=db"},
	} {
		if e := wantCode(t, "WRONG_KIND", args...); !strings.Contains(e.Message, "r1 is a redis cache") {
			t.Errorf("%v: %q", args, e.Message)
		}
	}
}
