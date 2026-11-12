package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// applyLab is a loopback API with ConfigMaps and Deployments that refuses
// any object named "bad" (422), like a typo in a real file. It counts the
// PATCHes it gets, real and dry-run.
type applyLab struct {
	mu        sync.Mutex
	real, dry []string
	srv       *httptest.Server
}

func newApplyLab(t *testing.T) *applyLab {
	t.Helper()
	l := &applyLab{}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/api/v1":
			io.WriteString(w, `{"resources":[{"name":"configmaps","kind":"ConfigMap","namespaced":true,"shortNames":["cm"]},{"name":"pods","kind":"Pod","namespaced":true}]}`)
		case p == "/apis":
			io.WriteString(w, `{"groups":[{"preferredVersion":{"groupVersion":"apps/v1"}}]}`)
		case p == "/apis/apps/v1":
			io.WriteString(w, `{"resources":[{"name":"deployments","kind":"Deployment","namespaced":true,"shortNames":["deploy"]}]}`)
		case r.Method == "PATCH":
			name := p[strings.LastIndex(p, "/")+1:]
			l.mu.Lock()
			if r.URL.Query().Get("dryRun") == "All" {
				l.dry = append(l.dry, name)
			} else {
				l.real = append(l.real, name)
			}
			l.mu.Unlock()
			if name == "bad" {
				w.WriteHeader(422)
				io.WriteString(w, `{"reason":"Invalid","code":422,"message":"ConfigMap \"bad\" is invalid: data: Invalid value"}`)
				return
			}
			b, _ := io.ReadAll(r.Body)
			w.Write(b)
		case r.Method == "GET" && strings.HasSuffix(p, "/pods"):
			io.WriteString(w, `{"items":[]}`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","code":404,"message":"not found"}`)
		}
	}))
	t.Cleanup(l.srv.Close)
	return l
}

func (l *applyLab) kubeconfig(t *testing.T, user string) string {
	t.Helper()
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: " + l.srv.URL +
		"\nusers:\n- name: prod\n  user:\n" + user + "\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: prod\n    namespace: shop\n"
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A real apply checks the whole file with the server first: when one
// object is refused, nothing in the file is applied (before, the objects
// above it were, and the file was left half applied).
func TestClusterApplyChecksTheWholeFileFirst(t *testing.T) {
	invHome(t)
	l := newApplyLab(t)
	mustRun(t, "import", "kubeconfig", l.kubeconfig(t, "    token: test-token-abcdef"))
	file := filepath.Join(t.TempDir(), "app.yaml")
	yaml := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: good}\ndata: {a: b}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: bad}\ndata: {a: b}\n"
	if err := os.WriteFile(file, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, e := cliRun(t, "cluster", "apply", "prod", "--file", file)
	if e == nil || e.Code != "K8S_INVALID" || !strings.Contains(e.Message, "nothing was applied") || !strings.Contains(e.Message, "configmap/bad") {
		t.Fatalf("want K8S_INVALID naming configmap/bad and saying nothing was applied, got %+v", e)
	}
	if len(l.real) != 0 {
		t.Errorf("a file with a refused object applied %v for real", l.real)
	}
	// a good file: checked first, then applied, each object once for real
	if err := os.WriteFile(file, []byte(strings.ReplaceAll(yaml, "name: bad", "name: also-good")), 0o600); err != nil {
		t.Fatal(err)
	}
	d, e := cliRun(t, "cluster", "apply", "prod", "--file", file)
	if e != nil {
		t.Fatalf("%s %s", e.Code, e.Message)
	}
	if got := strings.Join(l.real, ","); got != "good,also-good" {
		t.Errorf("applied for real: %q", got)
	}
	if b, _ := json.Marshal(d["applied"]); string(b) != `["configmap/good","configmap/also-good"]` {
		t.Errorf("applied: %s", b)
	}
}
