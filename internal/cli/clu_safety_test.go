package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// labCluster is a loopback Kubernetes API with a Secret, a Deployment whose
// env holds a password, and pods that stream logs; it records requests.
type labCluster struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

func (l *labCluster) seen(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.reqs {
		if strings.Contains(r, sub) {
			n++
		}
	}
	return n
}

func newLabCluster(t *testing.T) *labCluster {
	t.Helper()
	l := &labCluster{}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	secret := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "app-db", "namespace": "shop"},
		"data": map[string]any{"DATABASE_URL": b64("postgres://app:Pr0dPw@db/app"), "username": b64("app_admin")}}
	env := []any{map[string]any{"name": "DB_PASSWORD", "value": "Sup3rS3cretPw"}, map[string]any{"name": "LOG_LEVEL", "value": "debug"},
		map[string]any{"name": "API_TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "t", "key": "k"}}}}
	applied, _ := json.Marshal(map[string]any{"kind": "Deployment", "spec": map[string]any{"template": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "api", "env": env}}}}}})
	deploy := map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "api", "namespace": "shop", "annotations": map[string]any{lastApplied: string(applied)}},
		"spec": map[string]any{"replicas": 2, "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "env": env}}}}}}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.reqs = append(l.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		l.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch p := r.URL.Path; {
		case p == "/api/v1":
			io.WriteString(w, `{"resources":[{"name":"secrets","kind":"Secret","namespaced":true},{"name":"pods","kind":"Pod","namespaced":true,"shortNames":["po"]},{"name":"serviceaccounts","kind":"ServiceAccount","namespaced":true,"shortNames":["sa"]}]}`)
		case p == "/apis":
			io.WriteString(w, `{"groups":[{"preferredVersion":{"groupVersion":"apps/v1"}}]}`)
		case p == "/apis/apps/v1":
			io.WriteString(w, `{"resources":[{"name":"deployments","kind":"Deployment","namespaced":true,"shortNames":["deploy"]}]}`)
		case strings.HasSuffix(p, "/secrets") && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"items": []any{secret}})
		case strings.HasSuffix(p, "/deployments/api") && r.Method == "GET":
			json.NewEncoder(w).Encode(deploy)
		case strings.HasSuffix(p, "/pods") && r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"items": []any{
				map[string]any{"metadata": map[string]any{"name": "pod-a"}}, map[string]any{"metadata": map[string]any{"name": "pod-b"}}}})
		case strings.HasSuffix(p, "/pods/gone/log"):
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","message":"pods \"gone\" not found"}`)
		case strings.HasSuffix(p, "/log"):
			pod := strings.Split(p, "/")[6]
			fl, _ := w.(http.Flusher)
			for i := 0; ; i++ {
				if _, err := fmt.Fprintf(w, "%s line %d\n", pod, i); err != nil {
					return
				}
				fl.Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(5 * time.Millisecond):
				}
				if r.URL.Query().Get("follow") != "true" && i == 2 {
					return
				}
			}
		case r.Method != "GET":
			io.WriteString(w, `{"status":{"token":"eyJreal.token.minted"}}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","message":"`+p+`"}`)
		}
	}))
	t.Cleanup(func() { l.srv.CloseClientConnections(); l.srv.Close() })
	return l
}

func (l *labCluster) client(t *testing.T) *kube.Client {
	t.Helper()
	x := &kube.Context{Namespace: "shop"}
	x.Cluster.Server = l.srv.URL
	k, err := kube.New(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// kubeconfigFile writes a kubeconfig for the lab with user (YAML under
// `user:`) and returns its path.
func (l *labCluster) kubeconfigFile(t *testing.T, user string) string {
	t.Helper()
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: " + l.srv.URL +
		"\nusers:\n- name: prod\n  user:\n" + user + "\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: prod\n    namespace: shop\n"
	p := filepath.Join(t.TempDir(), "k3s.yaml")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// cliRun is invRun with a fresh approval for every command, as each
// command is its own process in real use.
func cliRun(t *testing.T, args ...string) (map[string]any, *out.Error) {
	t.Helper()
	resetApproval()
	clear(safetyApproved)
	return invRun(t, args...)
}

// K1, K8: under --dry-run, `cluster run` sends nothing the server would not
// dry-run itself: no Secret read, no token, on a protected conn as an agent.
func TestClusterRunDryRunSendsNothingReal(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	mustRun(t, "conn", "edit", "prod", "--protected")
	windows := asAgent(t, false, false)
	for _, c := range []struct {
		args []string
		sent string
	}{
		{[]string{"create", "token", "bot", "--duration", "8760h"}, "/token"},
		{[]string{"create", "-n", "kube-system", "token", "admin"}, "/token"},
		{[]string{"config", "view", "--raw"}, "GET"},
		{[]string{"exec", "pod-a", "--", "id"}, "/exec"},
	} {
		before := l.seen(c.sent)
		d, e := cliRun(t, append([]string{"--dry-run", "cluster", "run", "prod", "--"}, c.args...)...)
		if e != nil {
			t.Errorf("%v: %s %s", c.args, e.Code, e.Message)
			continue
		}
		if n := l.seen(c.sent); n != before {
			t.Errorf("%v: a dry run sent %d real request(s) for %s", c.args, n-before, c.sent)
		}
		if d["would_run"] == nil || d["stdout"] != nil {
			t.Errorf("%v: want only the plan, got %v", c.args, d)
		}
		if m, _ := d["_meta"].(map[string]any); m["would_be_blocked"] == nil {
			t.Errorf("%v: the stop must be reported: %v", c.args, d)
		}
	}
	if *windows != 0 {
		t.Errorf("a dry run opened %d approval windows", *windows)
	}
	// K1: an agent sees Secret values hidden, so reading them is a read: it
	// runs, with no person asked, and shows no value
	for _, args := range [][]string{{"get", "secrets", "-A", "-o", "json"}, {"get", "secrets", "-o", "yaml"}} {
		d, e := cliRun(t, append([]string{"cluster", "run", "prod", "--"}, args...)...)
		if e != nil {
			t.Errorf("%v: %s %s", args, e.Code, e.Message)
			continue
		}
		if so, _ := d["stdout"].(string); !strings.Contains(so, "app-db") || strings.Contains(so, base64.StdEncoding.EncodeToString([]byte("app_admin"))) {
			t.Errorf("%v: %q", args, so)
		}
	}
	if *windows != 0 {
		t.Errorf("a masked Secret read asked a person %d times", *windows)
	}
	// what the server dry-runs itself still goes there, with dryRun=All
	if _, e := cliRun(t, "--dry-run", "cluster", "run", "prod", "--", "scale", "deploy/api", "--replicas=3"); e != nil {
		t.Fatalf("scale dry run: %s %s", e.Code, e.Message)
	}
	if l.seen("/deployments/api/scale?dryRun=All") != 1 || l.seen("PATCH") != 1 {
		t.Errorf("server dry run: %v", l.reqs)
	}
}

// K8: kctl itself never sends a TokenRequest under --dry-run.
func TestKctlCreateTokenDryRun(t *testing.T) {
	l := newLabCluster(t)
	saved := g.dryRun
	g.dryRun = true
	defer func() { g.dryRun = saved }()
	code, so, se := runKctl(context.Background(), l.client(t), "lab", []string{"create", "token", "bot"})
	if code == 0 || strings.Contains(so, "eyJ") || !strings.Contains(se, "cannot be dry-run") || l.seen("/token") != 0 {
		t.Errorf("create token dry run: %d %q %q %v", code, so, se, l.reqs)
	}
}

// K1, K6: what kctl prints for an agent has no Secret values and no value
// of an env var named like a secret, in every output format.
func TestKctlGetMasksForAgents(t *testing.T) {
	l := newLabCluster(t)
	k := l.client(t)
	saved := out.P.Mask
	defer func() { out.P.Mask = saved }()
	leaks := []string{"Sup3rS3cretPw", base64.StdEncoding.EncodeToString([]byte("app_admin")), base64.StdEncoding.EncodeToString([]byte("postgres://app:Pr0dPw@db/app"))}
	for _, args := range [][]string{
		{"get", "secrets", "-o", "json"},
		{"get", "secrets", "-o", "yaml"},
		{"get", "secret", "app-db", "-o", "jsonpath={.data.username}"},
		{"get", "deploy", "api", "-o", "yaml"},
		{"get", "deploy", "api", "-o", "json"},
		{"get", "deploy", "api", "-o", "jsonpath={.spec.template.spec.containers[0].env[0].value}"},
	} {
		out.P.Mask = true
		_, so, se := runKctl(context.Background(), k, "lab", args)
		for _, s := range leaks {
			if strings.Contains(so, s) {
				t.Errorf("%v shows %q to an agent:\n%s%s", args, s, so, se)
			}
		}
		if args[1] == "deploy" && oneOf(args[4], "yaml", "json") && !strings.Contains(so, "debug") {
			t.Errorf("%v: values not named like secrets stay: %s", args, so)
		}
	}
	// a person sees what they asked for
	out.P.Mask = false
	if _, so, _ := runKctl(context.Background(), k, "lab", []string{"get", "deploy", "api", "-o", "yaml"}); !strings.Contains(so, "Sup3rS3cretPw") {
		t.Errorf("unmasked output changed: %s", so)
	}
}

// K6: `cluster get` hides env values named like secrets from an agent, also
// in the last-applied-configuration copy.
func TestClusterGetHidesSecretEnv(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	asAgent(t, false, false)
	d, e := cliRun(t, "cluster", "get", "prod", "deploy", "api")
	if e != nil {
		t.Fatalf("%s %s", e.Code, e.Message)
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "Sup3rS3cretPw") || !strings.Contains(string(b), "debug") {
		t.Errorf("cluster get for an agent: %s", b)
	}
}

func TestHideSecretEnv(t *testing.T) {
	o := map[string]any{"env": []any{
		map[string]any{"name": "DB_PASSWORD", "value": "x1"},
		map[string]any{"name": "STRIPE_SECRET_KEY", "value": "x2"},
		map[string]any{"name": "Authorization", "value": "Bearer x3abcdefghijklmnop"},
		map[string]any{"name": "LOG_LEVEL", "value": "debug"},
		map[string]any{"name": "PASSWORD_FILE", "value": "/run/secrets/pw"},
		map[string]any{"name": "USE_TOKEN_AUTH", "value": "true"},
		map[string]any{"name": "DB_PASSWORD_REF", "value": "secret:prod-db"},
		map[string]any{"name": "TOKEN", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "s"}}},
	}}
	hideSecretEnv(o)
	b, _ := json.Marshal(o)
	for _, s := range []string{"x1", "x2", "x3"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%s still shows: %s", s, b)
		}
	}
	// what text masking keeps stays too: true/false, a path, a reference
	for _, s := range []string{"debug", "secretKeyRef", `"true"`, "/run/secrets/pw", "secret:prod-db"} {
		if !strings.Contains(string(b), s) {
			t.Errorf("too much hidden (%s): %s", s, b)
		}
	}
}

// K2: a tar stream from the container cannot write outside DST.
func TestUntarToStaysInside(t *testing.T) {
	type ent struct{ name, body string }
	mk := func(es ...ent) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, e := range es {
			if strings.HasSuffix(e.name, "/") {
				tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeDir, Mode: 0o755})
				continue
			}
			tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(e.body))})
			tw.Write([]byte(e.body))
		}
		tw.Close()
		return b.Bytes()
	}
	root := t.TempDir()
	work := filepath.Join(root, "home", "proj", "app")
	os.MkdirAll(filepath.Join(root, "out"), 0o755)
	os.MkdirAll(work, 0o755)
	t.Chdir(work)
	bad := []struct {
		dst, base string
		tarball   []byte
	}{
		{".", "app", mk(ent{"../../.zshrc", "evil"})},
		{".", "app", mk(ent{"app/ok", "fine"}, ent{"app/../../../evil", "evil"})},
		{"..", "app", mk(ent{"../../evil", "evil"})},
		{filepath.Join(root, "out"), "app", mk(ent{"../out-evil/x", "evil"})},
		{filepath.Join(root, "out"), "app", mk(ent{"app../out-evil", "evil"})},
		{filepath.Join(root, "out"), "app", mk(ent{"other/x", "evil"})},
		{filepath.Join(root, "out"), "app", mk(ent{"/etc/x", "evil"})},
		{filepath.Join(root, "out"), "f", mk(ent{"f", "a"}, ent{"f/../../evil", "evil"})},
	}
	for i, c := range bad {
		if err := untarTo(c.tarball, c.dst, c.base); err == nil {
			t.Errorf("case %d (%s): accepted", i, c.dst)
		}
	}
	filepath.Walk(root, func(p string, fi os.FileInfo, _ error) error {
		if fi != nil && !fi.IsDir() {
			t.Errorf("a refused stream wrote %s", p)
		}
		return nil
	})
	// a link already under DST does not lead out either
	os.Symlink(filepath.Join(root, "home"), filepath.Join(root, "out", "sub"))
	if err := untarTo(mk(ent{"app/", ""}, ent{"app/sub/.zshrc", "evil"}), filepath.Join(root, "out"), "app"); err == nil {
		t.Error("followed a symbolic link out of DST")
	}
	if _, err := os.Stat(filepath.Join(root, "home", ".zshrc")); err == nil {
		t.Error("wrote through the link")
	}
	os.Remove(filepath.Join(root, "out", "sub"))

	// what kubectl cp does normally still works
	if err := untarTo(mk(ent{"report.txt", "r"}), ".", "report.txt"); err != nil {
		t.Errorf("cp POD:/report.txt . : %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(work, "report.txt")); string(b) != "r" {
		t.Errorf("single file into the cwd: %q", b)
	}
	dst := filepath.Join(root, "out", "copy")
	if err := untarTo(mk(ent{"data/", ""}, ent{"data/a/b.txt", "b"}), dst, "data"); err != nil {
		t.Errorf("folder copy: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "a", "b.txt"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("folder copy: %v %v (the mode is kept, as kubectl cp does)", fi, err)
	}
	if err := untarTo(mk(ent{"x", "1"}), filepath.Join(root, "out", "renamed.txt"), "x"); err != nil {
		t.Errorf("cp POD:/x DST-FILE: %v", err)
	}

	// nothing goes into a .git folder: its config and hooks run commands
	repo := filepath.Join(root, "repo")
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o644)
	for _, c := range []struct{ base, name string }{{"src", "src/.git/config"}, {"src", "src/sub/.GIT/hooks/pre-commit"}, {".git", ".git"}} {
		if err := untarTo(mk(ent{c.name, "[core]\n\tfsmonitor = evil\n"}), repo, c.base); err == nil {
			t.Errorf("%s: wrote into .git", c.name)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(repo, ".git", "config")); string(b) != "[core]\n" {
		t.Errorf(".git/config changed: %q", b)
	}
	// a file already there gets the copied file's mode, no exec bit of its own
	run := filepath.Join(repo, "run.sh")
	os.WriteFile(run, []byte("old"), 0o755)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "run.sh", Typeflag: tar.TypeReg, Mode: 0o6646, Size: 3})
	tw.Write([]byte("new"))
	tw.Close()
	if err := untarTo(b.Bytes(), run, "run.sh"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(run); fi.Mode() != 0o644 {
		t.Errorf("run.sh: %v, want -rw-r--r-- (no setuid, setgid, world-write, kept exec bit)", fi.Mode())
	}
}

// K3: delete -f deletes in the file's namespace, and refuses a -n that
// says otherwise.
func TestKctlDeleteFileNamespace(t *testing.T) {
	f := &fakeAPI{}
	k := f.client(t) // the conn's namespace is shop
	file := filepath.Join(t.TempDir(), "app.yaml")
	os.WriteFile(file, []byte("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: payments\n---\napiVersion: v1\nkind: Node\nmetadata:\n  name: n1\n"), 0o600)
	code, so, se := runKctl(context.Background(), k, "lab", []string{"delete", "-f", file, "--wait=false"})
	all := strings.Join(f.writes, "\n")
	if code != 0 || !strings.Contains(all, "DELETE /apis/apps/v1/namespaces/payments/deployments/web") || strings.Contains(all, "/namespaces/shop/") ||
		!strings.Contains(all, "DELETE /api/v1/nodes/n1") {
		t.Errorf("delete -f: %d %q %q\n%s", code, so, se, all)
	}
	if !strings.Contains(so, `deployment.apps "web" deleted from payments namespace`) || !strings.Contains(so, `node "n1" deleted`+"\n") {
		t.Errorf("the output names the namespace: %q", so)
	}
	f.writes = nil
	code, _, se = runKctl(context.Background(), k, "lab", []string{"delete", "-f", file, "-n", "shop", "--wait=false"})
	if code == 0 || !strings.Contains(se, "does not match the namespace") || len(f.writes) != 0 {
		t.Errorf("a contradicting -n: %d %q %v", code, se, f.writes)
	}
	// an empty name would be DELETE on the whole collection: never sent
	empty := filepath.Join(t.TempDir(), "empty.yaml")
	os.WriteFile(empty, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: \"\"\n"), 0o600)
	for _, args := range [][]string{
		{"delete", "-f", empty},
		{"delete", "pod", ""},
		{"delete", "pod/"},
		{"delete", "pod", "a", ""},
		{"patch", "pod", "", "-p", "{}"},
		{"replace", "-f", empty},
		{"scale", "deploy/", "--replicas=1"},
	} {
		f.writes = nil
		code, _, se := runKctl(context.Background(), k, "lab", append(args, "--wait=false"))
		if code == 0 || len(f.writes) != 0 {
			t.Errorf("%q: %d %q, sent %v", args, code, se, f.writes)
		}
	}
}

// K4: scale is rated by the number kctl sends, and only that number goes.
func TestScaleRatedByNumber(t *testing.T) {
	for cmd, want := range map[string]driver.Risk{
		"scale deploy/web --replicas=2":               driver.RiskWrite,
		"scale deploy/web --replicas 2":               driver.RiskWrite,
		"scale deploy/web --replicas=0":               driver.RiskDestructive,
		"scale deploy/web --replicas 0":               driver.RiskDestructive,
		"scale deploy/web --replicas=-0":              driver.RiskDestructive,
		"scale deploy/web --replicas -0":              driver.RiskDestructive,
		"scale deploy/web --replicas=00":              driver.RiskDestructive,
		"scale deploy/web --replicas=+0":              driver.RiskDestructive,
		"scale deploy/web --replicas=3 --replicas=0":  driver.RiskDestructive,
		"scale deploy/web --replicas=0 --replicas=3":  driver.RiskWrite,
		"scale deploy/web --replicas=-1":              driver.RiskDestructive,
		"scale deploy/web":                            driver.RiskDestructive, // no count: not a number
		"scale deploy/web --replicas=two":             driver.RiskDestructive,
		"create -n kube-system token admin":           driver.RiskDestructive,
		"create --namespace=x clusterrolebinding a b": driver.RiskDestructive,
	} {
		if got := classifyKubectl(strings.Fields(cmd)); got != want {
			t.Errorf("kubectl %s: %v, want %v", cmd, got, want)
		}
	}
	f := &fakeAPI{}
	k := f.client(t)
	for in, body := range map[string]string{"-0": `{"spec":{"replicas":0}}`, "00": `{"spec":{"replicas":0}}`, "+3": `{"spec":{"replicas":3}}`} {
		f.writes = nil
		if code, _, se := runKctl(context.Background(), k, "lab", []string{"scale", "deploy/web", "--replicas=" + in}); code != 0 || !strings.Contains(strings.Join(f.writes, ""), body) {
			t.Errorf("--replicas=%s: %d %q %v", in, code, se, f.writes)
		}
	}
	f.writes = nil
	if code, _, _ := runKctl(context.Background(), k, "lab", []string{"scale", "deploy/web", "--replicas=-1"}); code == 0 || len(f.writes) != 0 {
		t.Errorf("a negative count reached the server: %v", f.writes)
	}
}

// K5: every docker command that hands a container the server is rated
// destructive, whichever verb or flag spelling makes it.
func TestClassifyDockerHostEscapes(t *testing.T) {
	for cmd, want := range map[string]driver.Risk{
		"create --privileged --name x alpine sleep 1d":                          driver.RiskDestructive,
		"container create --privileged alpine":                                  driver.RiskDestructive,
		"service create --mode global --mount type=bind,source=/,target=/h a":   driver.RiskDestructive,
		"service create --mount type=bind,source=/var/run/docker.sock,dst=/s a": driver.RiskDestructive,
		"service create --cap-add ALL alpine":                                   driver.RiskDestructive,
		"service update --mount-add type=bind,source=/,target=/h web":           driver.RiskDestructive,
		"run -v/:/host alpine":                                                  driver.RiskDestructive,
		"run -itv/:/host alpine sh":                                             driver.RiskDestructive,
		"run --mount type=bind,src=/,target=/h alpine":                          driver.RiskDestructive,
		"run --mount=type=bind,src=/,dst=/h alpine":                             driver.RiskDestructive,
		"container run --mount type=bind,src=/,dst=/h alpine":                   driver.RiskDestructive,
		"run -v /etc:/x alpine":                                                 driver.RiskDestructive,
		"run -v /var/run:/r alpine":                                             driver.RiskDestructive,
		"run --volume=/root/.ssh:/k alpine":                                     driver.RiskDestructive,
		"plugin install --grant-all-permissions vieux/sshfs":                    driver.RiskDestructive,
		"service scale web=0":                                                   driver.RiskDestructive,
		"service scale api=2 web=-0":                                            driver.RiskDestructive,
		"service update --replicas 0 web":                                       driver.RiskDestructive,
		"service update --replicas=0 web":                                       driver.RiskDestructive,
		// ordinary containers and services stay writes
		"run -d -v /srv/app:/app nginx":                          driver.RiskWrite,
		"run -d -v data:/data nginx":                             driver.RiskWrite,
		"run -d -v /etc/localtime:/etc/localtime:ro nginx":       driver.RiskWrite,
		"run -e -v=x nginx":                                      driver.RiskWrite,
		"create --name x nginx":                                  driver.RiskWrite,
		"service create --replicas 2 --name web nginx":           driver.RiskWrite,
		"service create --mount type=volume,src=data,dst=/d web": driver.RiskWrite,
		"service scale web=3":                                    driver.RiskWrite,
		"service update --replicas 3 web":                        driver.RiskWrite,
		"service update --image nginx:2 web":                     driver.RiskWrite,
	} {
		if got := classifyDocker(strings.Fields(cmd)); got != want {
			t.Errorf("docker %s: %v, want %v", cmd, got, want)
		}
	}
}

// K7: a kubeconfig login program is a program on this computer: an agent
// brings it in, or runs it, only with a person's yes.
func TestKubeconfigLoginProgramNeedsAPerson(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	marker := filepath.Join(t.TempDir(), "ran")
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/sh\n      args: [\"-c\", \"echo ran > " + marker +
		"; echo '{\\\"status\\\":{\\\"token\\\":\\\"t\\\"}}'\"]\n"
	file := l.kubeconfigFile(t, plugin)
	ran := func() bool { _, err := os.Stat(marker); return err == nil }

	windows := asAgent(t, false, false)
	if _, e := cliRun(t, "import", "kubeconfig", file); e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("an agent's import: %+v", e)
	}
	if d, e := cliRun(t, "--dry-run", "import", "kubeconfig", file); e != nil || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("an agent's dry-run import reports the stop: %v %+v", d, e)
	}
	noAgent(t)
	mustRun(t, "import", "kubeconfig", file) // a person brought it in, and trusts it
	// then the kubeconfig in the vault changes (an agent's secret set):
	// the person did not trust that program
	kc, _ := vault.Get("prod-kubeconfig")
	if err := vault.Set("prod-kubeconfig", strings.Replace(kc, "echo ran", "echo ran2", 1)); err != nil || !strings.Contains(kc, "echo ran") {
		t.Fatalf("vault: %v %q", err, kc)
	}
	t.Setenv("CLAUDECODE", "1")
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Message, "/bin/sh -c") {
		t.Errorf("an agent's read runs the program without a yes: %+v", e)
	}
	if d, e := cliRun(t, "--dry-run", "cluster", "ls", "prod", "pods"); e != nil || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run: %v %+v", d, e)
	}
	if d, e := cliRun(t, "--dry-run", "cluster", "run", "prod", "--", "get", "pods"); e != nil || d["would_run"] == nil {
		t.Errorf("dry run of cluster run: %v %+v", d, e)
	}
	if ran() || l.seen("/pods") != 0 {
		t.Fatal("the login program ran without a person's yes")
	}
	if *windows != 0 {
		t.Errorf("without --yes nobody is asked: %d windows", *windows)
	}
	// with the person's yes it runs
	asAgent(t, true, true)
	if _, e := cliRun(t, "--yes", "cluster", "ls", "prod", "pods"); e != nil || !ran() {
		t.Errorf("approved: %+v ran=%v", e, ran())
	}
	// a person's own commands run it as they wired it
	os.Remove(marker)
	noAgent(t)
	if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e != nil || !ran() {
		t.Errorf("a person: %+v ran=%v", e, ran())
	}
}

func TestKubePluginRules(t *testing.T) {
	x := &kube.Context{}
	if x.Plugin() != nil {
		t.Error("no plugin")
	}
	for _, c := range []struct {
		cmd     string
		args    []string
		builtin bool
	}{
		{"aws", []string{"eks", "get-token", "--cluster-name", "c"}, true},
		{"/usr/local/bin/aws", []string{"--region", "x", "eks", "get-token", "--cluster-name", "c"}, true},
		{"aws", []string{"s3", "cp", "x", "y"}, false},
		{"aws-iam-authenticator", []string{"token", "-i", "c"}, true},
		{"aws-iam-authenticator", []string{"token"}, false},
		{"gke-gcloud-auth-plugin", nil, true},
		{"kubelogin", []string{"get-token"}, false},
		{"/bin/sh", []string{"-c", "id"}, false},
	} {
		x.User.Exec = &kube.ExecAuth{Command: c.cmd, Args: c.args}
		if got := x.Plugin() == nil; got != c.builtin {
			t.Errorf("%s %v: komando makes the token itself = %v, want %v", c.cmd, c.args, got, c.builtin)
		}
	}
	x.User.Exec = &kube.ExecAuth{Command: "kubelogin", Env: []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	}{{"PATH", "/tmp/evil"}}}
	if l := pluginLine(x.User.Exec); l != "PATH=/tmp/evil kubelogin" {
		t.Errorf("the line shows the environment it runs with: %q", l)
	}
	// a destructive program is refused for everyone
	x.User.Exec = &kube.ExecAuth{Command: "sh", Args: []string{"-c", "rm -rf /"}}
	if err := guardKubePlugin(&store.Conn{Name: "c"}, x); err == nil || toErr(err).Code != "POLICY_BLOCKED" {
		t.Errorf("destructive login program: %v", err)
	}
}

// K7: an agent's kubeconfig cannot send a file of this computer as its token.
func TestKubeconfigTokenFileNeedsAPerson(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	tok := filepath.Join(t.TempDir(), "private")
	os.WriteFile(tok, []byte("local-secret"), 0o600)
	asAgent(t, false, false)
	if _, e := cliRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    tokenFile: "+tok)); e == nil || e.Code != "SAFETY_SETTING" {
		t.Errorf("tokenFile import by an agent: %+v", e)
	}
}

// K9: a port forward on a protected cluster needs the person's yes, like a shell.
func TestClusterForwardProtected(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	mustRun(t, "conn", "edit", "prod", "--protected")
	d, e := cliRun(t, "--dry-run", "cluster", "forward", "prod", "svc/redis", "16379:6379")
	if e != nil {
		t.Fatalf("%+v", e)
	}
	wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any)
	if wb["code"] != "PROTECTED_TARGET" {
		t.Errorf("forward on a protected conn: %v", d)
	}
}

// K10: `cluster run -- logs -f` follows every pod at once and hands each
// line on as it comes; a timeout is a normal end.
func TestKctlFollowLogs(t *testing.T) {
	l := newLabCluster(t)
	k := l.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var mu sync.Mutex
	got := map[string]int{}
	first := time.Time{}
	start := time.Now()
	code, so, se, _ := runKctlLive(ctx, k, "lab", []string{"logs", "-l", "app=api", "-f", "--prefix"}, func(pod, prefix, line string) {
		mu.Lock()
		defer mu.Unlock()
		if first.IsZero() {
			first = time.Now()
		}
		if prefix != "[pod/"+pod+"] " {
			t.Errorf("prefix %q", prefix)
		}
		got[pod]++
	})
	mu.Lock()
	defer mu.Unlock()
	if code != 0 || so != "" || se != "" {
		t.Errorf("follow: %d %q %q", code, so, se)
	}
	if got["pod-a"] == 0 || got["pod-b"] == 0 {
		t.Errorf("every pod is followed at once: %v", got)
	}
	if first.IsZero() || first.Sub(start) > 300*time.Millisecond {
		t.Error("lines are handed on as they come, not at the end")
	}

	// without a live printer the lines are kept, up to a cap
	saved := maxFollowBytes
	maxFollowBytes = 200
	defer func() { maxFollowBytes = saved }()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	code, so, se = runKctl(ctx2, k, "lab", []string{"logs", "pod-a", "-f"})
	if code != 0 || len(so) > 200 || !strings.Contains(so, "pod-a line 0") || !strings.Contains(se, "dropped") {
		t.Errorf("capped follow: %d %d bytes %q", code, len(so), se)
	}
	if code, _, se := runKctl(context.Background(), k, "lab", []string{"logs", "-l", "app=api", "-f", "--max-log-requests", "1"}); code == 0 || !strings.Contains(se, "maximum allowed concurrency is 1") {
		t.Errorf("--max-log-requests: %d %q", code, se)
	}
}

// K11: a pod whose stream does not open is noted and the others go on;
// nothing is printed after streamPods returns.
func TestStreamPodsOnePodFails(t *testing.T) {
	l := newLabCluster(t)
	k := l.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var mu sync.Mutex
	var lines []string
	emit := func(pod, line string) {
		mu.Lock()
		lines = append(lines, pod+": "+line)
		mu.Unlock()
	}
	n, err := streamPods(ctx, k, "shop", []string{"pod-a", "gone"}, url.Values{}, emit)
	mu.Lock()
	at := len(lines)
	mu.Unlock()
	if err != nil || n == 0 {
		t.Fatalf("one pod failing stops the rest: %d %v", n, err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "gone: (no logs:") || !strings.Contains(joined, "pod-a: pod-a line 0") {
		t.Errorf("lines: %s", joined)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if len(lines) != at {
		t.Errorf("%d lines came after streamPods returned", len(lines)-at)
	}
	mu.Unlock()
	// when no stream opens, that is the error, and it comes at once
	if _, err := streamPods(context.Background(), k, "shop", []string{"gone"}, url.Values{}, emit); err == nil {
		t.Error("no stream opened, no error")
	}
}

// K5: --mount read as CSV, host-backed volumes, other containers' volumes,
// the host's network and cgroups, credential folders read-only, plugins.
func TestClassifyDockerMoreHostEscapes(t *testing.T) {
	for _, c := range []struct {
		args []string
		want driver.Risk
	}{
		{[]string{"run", "--mount", `type=bind,"source=/",target=/h`, "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--mount", `"type=bind","src=/etc",dst=/e`, "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--mount", `type=bind,src="/,dst=/h`, "alpine"}, driver.RiskDestructive}, // unreadable: the worst
		{[]string{"run", "--mount", "type=volume,dst=/h,volume-driver=local,volume-opt=type=none,volume-opt=o=bind,volume-opt=device=/", "alpine"}, driver.RiskDestructive},
		{[]string{"service", "create", "--mount", "type=volume,dst=/h,volume-opt=o=bind,volume-opt=device=/etc", "alpine"}, driver.RiskDestructive},
		{[]string{"volume", "create", "--driver", "local", "--opt", "type=none", "--opt", "o=bind", "--opt", "device=/", "rootfs"}, driver.RiskDestructive},
		{[]string{"volume", "create", "-o", "device=/var/lib/docker", "x"}, driver.RiskDestructive},
		{[]string{"volume", "create", "--opt=device=/root", "x"}, driver.RiskDestructive},
		{[]string{"run", "--volumes-from", "rootc", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--network=host", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--net", "host", "alpine"}, driver.RiskDestructive},
		{[]string{"service", "create", "--network", "host", "nginx"}, driver.RiskDestructive},
		{[]string{"run", "--cgroupns=host", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--pid", "container:priv", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "--device-cgroup-rule", "b 8:* rmw", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/var/spool/cron:/c", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/home:/h", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/home/deploy:/h:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/home/deploy/app/.ssh:/k:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/opt:/o", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/etc/kubernetes:/k:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/root:/r:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/etc:/e:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/var/lib/kubelet:/k:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"run", "-v", "/var:/v:ro", "alpine"}, driver.RiskDestructive},
		{[]string{"plugin", "create", "evil", "./ctx"}, driver.RiskDestructive},
		{[]string{"plugin", "enable", "evil"}, driver.RiskDestructive},
		{[]string{"plugin", "set", "evil", "mnt.source=/"}, driver.RiskDestructive},
		// ordinary ones stay writes
		{[]string{"run", "-d", "-v", "/etc/ssl/certs:/etc/ssl/certs:ro", "nginx"}, driver.RiskWrite},
		{[]string{"run", "-d", "-v", "/etc/timezone:/etc/timezone:ro", "nginx"}, driver.RiskWrite},
		{[]string{"run", "-d", "-v", "/home/deploy/app/data:/data", "nginx"}, driver.RiskWrite},
		{[]string{"run", "-d", "--network", "web", "nginx"}, driver.RiskWrite},
		{[]string{"run", "-d", "--mount", `type=bind,"source=/srv/app",target=/app`, "nginx"}, driver.RiskWrite},
		{[]string{"run", "-d", "--mount", "type=volume,src=data,dst=/d,volume-opt=type=nfs,volume-opt=device=:/export", "nginx"}, driver.RiskWrite},
		{[]string{"volume", "create", "--opt", "device=/srv/data", "--opt", "o=bind", "data"}, driver.RiskWrite},
		{[]string{"volume", "create", "data"}, driver.RiskWrite},
	} {
		if got := classifyDocker(c.args); got != c.want {
			t.Errorf("docker %q: %v, want %v", c.args, got, c.want)
		}
	}
}

// K1: `get secret -o yaml` prints values only when they are not hidden.
func TestGetSecretValuesRating(t *testing.T) {
	saved := out.P.Mask
	defer func() { out.P.Mask = saved }()
	args := strings.Fields("get secret app-db -o yaml")
	for mask, want := range map[bool]driver.Risk{true: driver.RiskRead, false: driver.RiskDestructive} {
		out.P.Mask = mask
		if got := classifyKubectl(args); got != want {
			t.Errorf("masked=%v: %v, want %v", mask, got, want)
		}
	}
}

// K6: an agent's round trip (get -o yaml, edit, apply) never writes the
// hidden marker over the real value: nothing is sent.
func TestApplyRefusesHiddenValues(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	asAgent(t, false, false)
	d, e := cliRun(t, "cluster", "run", "prod", "--", "get", "deploy", "api", "-o", "yaml")
	if e != nil {
		t.Fatalf("%s %s", e.Code, e.Message)
	}
	yml, _ := d["stdout"].(string)
	if !strings.Contains(yml, out.Hidden) {
		t.Fatalf("the agent's copy hides DB_PASSWORD: %s", yml)
	}
	file := filepath.Join(t.TempDir(), "api.yaml")
	os.WriteFile(file, []byte(strings.ReplaceAll(yml, "replicas: 2", "replicas: 3")), 0o600)
	for _, args := range [][]string{{"apply", "-f", file}, {"create", "-f", file}} {
		before := l.seen("PATCH") + l.seen("POST") + l.seen("PUT")
		_, e := cliRun(t, append([]string{"cluster", "run", "prod", "--write", "--"}, args...)...)
		if e == nil || e.Code != "HIDDEN_VALUE" || !strings.Contains(e.Hint, "set image") {
			t.Errorf("%v: %+v", args, e)
		}
		if n := l.seen("PATCH") + l.seen("POST") + l.seen("PUT"); n != before {
			t.Errorf("%v sent %d writes", args, n-before)
		}
	}
	if _, e := cliRun(t, "cluster", "apply", "prod", "--file", file); e == nil || e.Code != "HIDDEN_VALUE" {
		t.Errorf("cluster apply: %+v", e)
	}
	if code, _, se := runKctl(context.Background(), l.client(t), "lab", []string{"replace", "-f", file}); code == 0 || !strings.Contains(se, "komando hid") || l.seen("PUT") != 0 {
		t.Errorf("replace: %d %q", code, se)
	}
	// diff sends nothing that stays: it may compare
	if code, _, se := runKctl(context.Background(), l.client(t), "lab", []string{"diff", "-f", file}); strings.Contains(se, "komando hid") {
		t.Errorf("diff: %d %q", code, se)
	}
	// a Secret redacted by cluster get, "(hidden)", is refused as well
	sec := filepath.Join(t.TempDir(), "s.yaml")
	os.WriteFile(sec, []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-db\nstringData:\n  password: (hidden)\n"), 0o600)
	if _, e := cliRun(t, "cluster", "run", "prod", "--write", "--", "apply", "-f", sec); e == nil || e.Code != "HIDDEN_VALUE" {
		t.Errorf("(hidden) Secret: %+v", e)
	}
}

// new: an agent's kctl does not send komando's folder or a secret file of
// this computer to the cluster, where `get` would hand it back.
func TestKctlLocalSecretFiles(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef"))
	home := os.Getenv("KOMANDO_HOME")
	inHome := filepath.Join(home, "notes.yaml")
	os.WriteFile(inHome, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"), 0o600)
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("DB_PASSWORD=x"), 0o600)
	secrets := filepath.Join(dir, "secrets.yaml")
	os.WriteFile(secrets, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: y\n"), 0o600)
	asAgent(t, false, false)
	for _, args := range [][]string{
		{"create", "configmap", "x", "--from-file=" + inHome},
		{"create", "configmap", "x", "--from-file=k=" + env},
		{"create", "secret", "generic", "x", "--from-file=" + env},
		{"apply", "-f", inHome},
		{"apply", "-f", home},
		{"apply", "-f", secrets},
		{"apply", "-f", dir},
	} {
		before := l.seen("POST") + l.seen("PATCH") + l.seen("/exec")
		_, e := cliRun(t, append([]string{"cluster", "run", "prod", "--write", "--"}, args...)...)
		if e == nil || e.Code != "SENSITIVE_FILE" {
			t.Errorf("%v: %+v", args, e)
		}
		if n := l.seen("POST") + l.seen("PATCH") + l.seen("/exec"); n != before {
			t.Errorf("%v sent %d requests", args, n-before)
		}
	}
	// cp to a pod (destructive, so through kctl here)
	if code, _, se := runKctl(context.Background(), l.client(t), "lab", []string{"cp", dir, "pod-a:/tmp/x"}); code == 0 || !strings.Contains(se, "holds secrets") || l.seen("/exec") != 0 {
		t.Errorf("cp: %d %q", code, se)
	}
	// the dry run reports the stop
	if d, e := cliRun(t, "--dry-run", "cluster", "run", "prod", "--write", "--", "apply", "-f", secrets); e != nil || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run: %v %+v", d, e)
	}
	// a person sends what they want
	noAgent(t)
	if _, e := cliRun(t, "cluster", "run", "prod", "--write", "--", "create", "secret", "generic", "x", "--from-file=k="+env); e != nil {
		t.Errorf("a person: %+v", e)
	}
}

// K7: the window names the program the agent's --yes lets run, and a yes
// given for something else (a protected conn) does not cover it.
func TestPluginApprovalNamesTheProgram(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	t.Setenv("CLAUDECODE", "1")
	var texts []string
	saved := askOnScreen
	askOnScreen = func(text string) (bool, bool) { texts = append(texts, text); return true, true }
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	marker := filepath.Join(t.TempDir(), "ran")
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/sh\n      args: [\"-c\", \"touch " + marker +
		"; echo '{\\\"status\\\":{\\\"token\\\":\\\"t\\\"}}'\"]\n"
	if _, e := cliRun(t, "--yes", "import", "kubeconfig", l.kubeconfigFile(t, plugin)); e != nil {
		t.Fatalf("approved import: %+v", e)
	}
	if len(texts) != 1 || !strings.Contains(texts[0], "/bin/sh -c touch "+marker) {
		t.Errorf("the import window shows the program: %q", texts)
	}
	// the conn is protected and the kubeconfig in the vault now runs
	// another program: one yes for the protected conn, one naming it
	noAgent(t)
	mustRun(t, "conn", "edit", "prod", "--protected")
	kc, err := vault.Get("prod-kubeconfig")
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set("prod-kubeconfig", strings.Replace(kc, "touch", "touch -c", 1)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDECODE", "1")
	texts = nil
	if _, e := cliRun(t, "--yes", "cluster", "run", "prod", "--write", "--", "scale", "deploy/api", "--replicas=3"); e != nil {
		t.Fatalf("%+v", e)
	}
	named := 0
	for _, x := range texts {
		if strings.Contains(x, "/bin/sh -c touch -c "+marker) {
			named++
		}
	}
	if named != 1 {
		t.Errorf("the program is named in exactly one window: %q", texts)
	}
}

// K7: a person's import trusts its program for agents' later commands; a
// change of program or server in the vault asks again; a dry run of
// exec, shell or forward reports the stop the real run would meet.
func TestTrustedKubePlugin(t *testing.T) {
	invHome(t)
	l := newLabCluster(t)
	plugin := "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/sh\n      args: [\"-c\", \"echo '{\\\"status\\\":{\\\"token\\\":\\\"t\\\"}}'\"]\n"
	mustRun(t, "import", "kubeconfig", l.kubeconfigFile(t, plugin)) // a person
	windows := asAgent(t, false, false)
	for _, args := range [][]string{{"cluster", "ls", "prod", "pods"}, {"cluster", "run", "prod", "--", "get", "pods"}} {
		if _, e := cliRun(t, args...); e != nil {
			t.Errorf("%v on a trusted conn: %+v", args, e)
		}
	}
	if *windows != 0 {
		t.Errorf("a trusted program asked %d times", *windows)
	}
	// --option cannot set the trust
	noAgent(t)
	kc, _ := vault.Get("prod-kubeconfig")
	for _, changed := range []string{strings.Replace(kc, "echo", "id; echo", 1), strings.Replace(kc, l.srv.URL, "https://attacker.example:6443", 1)} {
		vault.Set("prod-kubeconfig", changed)
		t.Setenv("CLAUDECODE", "1")
		if _, e := cliRun(t, "cluster", "ls", "prod", "pods"); e == nil || e.Code != "SAFETY_SETTING" || !strings.Contains(e.Hint, "read-only commands ask too") {
			t.Errorf("a changed kubeconfig runs without a yes: %+v", e)
		}
		for _, args := range [][]string{
			{"--dry-run", "cluster", "exec", "prod", "pod-a", "--", "id"},
			{"--dry-run", "cluster", "forward", "prod", "pod/pod-a", "18080:80"},
		} {
			d, e := cliRun(t, args...)
			wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any)
			if e != nil || wb["code"] != "SAFETY_SETTING" {
				t.Errorf("%v: %v %+v", args, d, e)
			}
		}
		noAgent(t)
	}
}

// K7: a yes in a window that did not name an action does not cover it.
func TestPersonAllowsForAsksAgain(t *testing.T) {
	t.Setenv("CLAUDECODE", "1")
	var texts []string
	saved := askOnScreen
	askOnScreen = func(text string) (bool, bool) { texts = append(texts, text); return true, true }
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	resetApproval()
	if !personAllows("--yes") || !personAllowsFor("--yes", "runs `x`") || !personAllowsFor("--yes", "runs `x`") || !personAllows("--allow-dangerous") {
		t.Fatal("allowed")
	}
	if len(texts) != 2 || strings.Contains(texts[0], "runs `x`") || !strings.Contains(texts[1], "runs `x`") {
		t.Errorf("windows: %q", texts)
	}
	// once denied, nothing else is asked
	resetApproval()
	texts = nil
	askOnScreen = func(text string) (bool, bool) { texts = append(texts, text); return false, true }
	if personAllows("--yes") || personAllowsFor("--yes", "runs `y`") || len(texts) != 1 {
		t.Errorf("after a no: %q", texts)
	}
}

// K7: the trust in a login program never comes from an export file.
func TestImportKomandoDropsTrustedPlugin(t *testing.T) {
	invHome(t)
	b, _ := json.Marshal(exportFile{Format: exportFormat, Conns: []*store.Conn{{Name: "k", Kind: "k8s", URL: "k8s://10.0.0.1:6443",
		PasswordRef: "secret:k-kubeconfig", TrustedPlugin: pluginTrust("/bin/sh -c id", "https://10.0.0.1:6443")}}})
	f := filepath.Join(t.TempDir(), "export.json")
	os.WriteFile(f, b, 0o600)
	mustRun(t, "import", "komando", f)
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Conns["k"]; c == nil || c.TrustedPlugin != "" {
		t.Errorf("imported conn: %+v", c)
	}
}
