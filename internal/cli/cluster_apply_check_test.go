package cli

import (
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
// PATCHes it gets, real and dry-run. An object named "owned" has a field
// another field manager owns: applying it without force=true is a
// conflict (409), as a real server says it.
type applyLab struct {
	mu        sync.Mutex
	real, dry []string
	forced    []string // the PATCHes sent with force=true
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
			force := r.URL.Query().Get("force") == "true"
			if force {
				l.forced = append(l.forced, name)
			}
			l.mu.Unlock()
			if name == "owned" && !force {
				w.WriteHeader(409)
				io.WriteString(w, `{"reason":"Conflict","code":409,"message":"Apply failed with 1 conflict: conflict with \"kubectl-edit\" using v1: .data.a","details":{"causes":[{"reason":"FieldManagerConflict","message":"conflict with \"kubectl-edit\" using v1","field":".data.a"}]}}`)
				return
			}
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
