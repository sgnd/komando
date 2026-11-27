package cli

import (
	"encoding/base64"
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

// detailCluster is a loopback Kubernetes API for `cluster kubernetes raw --
// describe`: a pod, a Deployment and a Secret whose data carries a value.
type detailCluster struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

const detailSecretValue = "Pr0dSecretPw"

func newDetailCluster(t *testing.T) *detailCluster {
	t.Helper()
	d := &detailCluster{}
	meta := func(name string, labels map[string]any) map[string]any {
		return map[string]any{"name": name, "namespace": "shop", "creationTimestamp": "2026-11-01T08:00:00Z", "labels": labels}
	}
	pod := map[string]any{"kind": "Pod", "metadata": meta("api-1", map[string]any{"app": "api"}),
		"spec":   map[string]any{"containers": []any{map[string]any{"name": "api", "image": "shop/api:1"}}, "nodeName": "node-1"},
		"status": map[string]any{"phase": "Running"}}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	secret := map[string]any{"kind": "Secret", "type": "Opaque", "metadata": meta("app-db", map[string]any{"app": "api"}),
		"data": map[string]any{"DB_PASSWORD": b64(detailSecretValue)}, "stringData": map[string]any{"OTHER": detailSecretValue}}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.reqs = append(d.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		switch p := r.URL.Path; {
		case p == "/api/v1":
			io.WriteString(w, `{"resources":[{"name":"pods","kind":"Pod","namespaced":true,"shortNames":["po"]},{"name":"secrets","kind":"Secret","namespaced":true},{"name":"events","kind":"Event","namespaced":true,"shortNames":["ev"]}]}`)
		case p == "/apis":
			io.WriteString(w, `{"groups":[]}`)
		case p == "/api/v1/namespaces/shop/secrets/app-db":
			enc.Encode(secret)
		case p == "/api/v1/namespaces/shop/pods/api-1":
			enc.Encode(pod)
		case p == "/api/v1/namespaces/shop/events":
			enc.Encode(map[string]any{"items": []any{}})
		default:
			w.WriteHeader(404)
			io.WriteString(w, `{"reason":"NotFound","message":"`+p+`"}`)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

// kubeconfig writes a kubeconfig for the fake API (context prod,
// namespace shop) and returns its path.
func (d *detailCluster) kubeconfig(t *testing.T) string {
	t.Helper()
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: prod\nclusters:\n- name: prod\n  cluster:\n    server: " + d.srv.URL +
		"\nusers:\n- name: prod\n  user:\n    token: test-token-abcdef\ncontexts:\n- name: prod\n  context:\n    cluster: prod\n    user: prod\n    namespace: shop\n"
	p := filepath.Join(t.TempDir(), "kubeconfig.yaml")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A Secret's values never show in `cluster kubernetes raw -- describe`,
// for a person or an agent, in JSON or text: not base64, not decoded.
// describe is a read, so no approval stands in front of this rule.
func TestRawDescribeSecretHasNoData(t *testing.T) {
	invHome(t)
	d := newDetailCluster(t)
	mustRun(t, "import", "kubeconfig", d.kubeconfig(t))
	leaks := []string{detailSecretValue, base64.StdEncoding.EncodeToString([]byte(detailSecretValue))}
	check := func(who string) {
		res, e := cliRun(t, "cluster", "kubernetes", "raw", "prod", "--", "describe", "secret", "app-db")
		if e != nil {
			t.Fatalf("%s: %s %s", who, e.Code, e.Message)
		}
		if so, _ := res["stdout"].(string); !strings.Contains(so, "app-db") || !strings.Contains(so, "Secret") {
			t.Errorf("%s: describe shows no Secret: %v", who, res)
		}
		b := jsonOf(res)
		for _, leak := range leaks {
			if strings.Contains(b, leak) {
				t.Errorf("%s: JSON shows the Secret's value: %s", who, b)
			}
		}
		s, err := runCache(t, "-o", "text", "cluster", "kubernetes", "raw", "prod", "--", "describe", "secret", "app-db")
		if err != nil {
			t.Fatalf("%s: text: %v", who, err)
		}
		for _, leak := range leaks {
			if strings.Contains(s, leak) {
				t.Errorf("%s: text shows the Secret's value: %s", who, s)
			}
		}
	}
	check("person")
	asAgent(t, false, false)
	check("agent")
}
