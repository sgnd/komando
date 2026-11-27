package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// detailCluster is a loopback Kubernetes API for `cluster describe` and
// `cluster logs`: a pod with labels, conditions and events, a second pod
// with two containers, a Deployment and a Secret. It records each request.
type detailCluster struct {
	mu   sync.Mutex
	reqs []string
	srv  *httptest.Server
}

const (
	detailSecretValue = "Pr0dSecretPw"
	detailLogs        = "2026-11-14T10:00:00.123456789Z starting api\n2026-11-14T10:00:01Z listening on :8080\n2026-11-14T10:00:02Z ready\n"
)

func (d *detailCluster) seen(sub string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, r := range d.reqs {
		if strings.Contains(r, sub) {
			n++
		}
	}
	return n
}

func newDetailCluster(t *testing.T) *detailCluster {
	t.Helper()
	d := &detailCluster{}
	meta := func(name string, labels map[string]any) map[string]any {
		return map[string]any{"name": name, "namespace": "shop", "creationTimestamp": "2026-11-01T08:00:00Z", "labels": labels}
	}
	cond := func(typ, status, reason, msg string) map[string]any {
		return map[string]any{"type": typ, "status": status, "reason": reason, "message": msg}
	}
	pod := func(name string, containers ...string) map[string]any {
		var cs, sts []any
		for _, c := range containers {
			cs = append(cs, map[string]any{"name": c, "image": "shop/" + c + ":1"})
			sts = append(sts, map[string]any{"name": c, "image": "shop/" + c + ":1", "ready": true, "restartCount": 0, "state": map[string]any{"running": map[string]any{}}})
		}
		return map[string]any{"kind": "Pod", "metadata": meta(name, map[string]any{"app": "api", "tier": "web"}),
			"spec":   map[string]any{"containers": cs, "nodeName": "node-1"},
			"status": map[string]any{"phase": "Running", "containerStatuses": sts, "conditions": []any{cond("Ready", "True", "", ""), cond("PodScheduled", "True", "", "")}}}
	}
	pods := map[string]map[string]any{"api-1": pod("api-1", "api"), "api-2": pod("api-2", "api", "sidecar")}
	deploy := map[string]any{"kind": "Deployment", "metadata": meta("api", map[string]any{"app": "api"}),
		"spec":   map[string]any{"replicas": 2, "selector": map[string]any{"matchLabels": map[string]any{"app": "api"}}, "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "shop/api:1"}}}}},
		"status": map[string]any{"readyReplicas": 1, "updatedReplicas": 2, "availableReplicas": 1, "conditions": []any{cond("Available", "False", "MinimumReplicasUnavailable", "Deployment does not have minimum availability.")}}}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	secret := map[string]any{"kind": "Secret", "type": "Opaque", "metadata": meta("app-db", map[string]any{"app": "api"}),
		"data": map[string]any{"DB_PASSWORD": b64(detailSecretValue)}, "stringData": map[string]any{"OTHER": detailSecretValue}}
	event := func(kind, name, typ, reason, msg string, count int, last string) map[string]any {
		return map[string]any{"type": typ, "reason": reason, "message": msg, "count": count, "lastTimestamp": last,
			"involvedObject": map[string]any{"kind": kind, "name": name}, "metadata": map[string]any{"namespace": "shop"}}
	}
	events := []any{
		event("Pod", "api-1", "Normal", "Pulled", "Container image already present", 1, "2026-11-14T09:59:58Z"),
		event("Pod", "api-1", "Warning", "BackOff", "Back-off restarting failed container", 4, "2026-11-14T09:59:59Z"),
		event("Deployment", "api", "Normal", "ScalingReplicaSet", "Scaled up replica set api-7d9f to 2", 1, "2026-11-14T09:00:00Z"),
	}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.reqs = append(d.reqs, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		p, q := r.URL.Path, r.URL.Query()
		switch {
		case p == "/api/v1":
			io.WriteString(w, `{"resources":[{"name":"pods","kind":"Pod","namespaced":true,"shortNames":["po"]},{"name":"secrets","kind":"Secret","namespaced":true},{"name":"events","kind":"Event","namespaced":true,"shortNames":["ev"]}]}`)
		case p == "/apis":
			io.WriteString(w, `{"groups":[{"preferredVersion":{"groupVersion":"apps/v1"}}]}`)
		case p == "/apis/apps/v1":
			io.WriteString(w, `{"resources":[{"name":"deployments","kind":"Deployment","namespaced":true,"shortNames":["deploy"]}]}`)
		case p == "/apis/apps/v1/namespaces/shop/deployments/api":
			enc.Encode(deploy)
		case p == "/api/v1/namespaces/shop/secrets/app-db":
			enc.Encode(secret)
		case p == "/api/v1/namespaces/shop/events":
			var items []any
			for _, e := range events {
				inv := e.(map[string]any)["involvedObject"].(map[string]any)
				fs := q.Get("fieldSelector")
				if strings.Contains(fs, "involvedObject.name="+str(inv["name"])) && strings.Contains(fs, "involvedObject.kind="+str(inv["kind"])) {
					items = append(items, e)
				}
			}
			enc.Encode(map[string]any{"items": items})
		case p == "/api/v1/namespaces/shop/pods":
			enc.Encode(map[string]any{"items": []any{pods["api-1"], pods["api-2"]}})
		case strings.HasPrefix(p, "/api/v1/namespaces/shop/pods/") && strings.HasSuffix(p, "/log"):
			name := strings.Split(p, "/")[6]
			if name == "api-2" && q.Get("container") == "" {
				w.WriteHeader(400)
				io.WriteString(w, `{"reason":"BadRequest","message":"a container name must be specified for pod api-2, choose one of: [api sidecar]"}`)
				return
			}
			lines := strings.SplitAfter(detailLogs, "\n")
			lines = lines[:len(lines)-1]
			if n, err := strconv.Atoi(q.Get("tailLines")); err == nil && n < len(lines) {
				lines = lines[len(lines)-n:]
			}
			w.Header().Set("Content-Type", "text/plain")
			for _, l := range lines {
				if q.Get("timestamps") != "true" {
					_, l, _ = strings.Cut(l, " ")
				}
				io.WriteString(w, l)
			}
		case strings.HasPrefix(p, "/api/v1/namespaces/shop/pods/"):
			if o, ok := pods[strings.TrimPrefix(p, "/api/v1/namespaces/shop/pods/")]; ok {
				enc.Encode(o)
				return
			}
			fallthrough
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

type dataMeta struct{ data, meta map[string]any }

// invRunMeta is invRun that also returns the envelope's meta.
func invRunMeta(t *testing.T, args ...string) (dataMeta, error) {
	t.Helper()
	s, err := runCache(t, append([]string{"-o", "json"}, args...)...)
	if err != nil {
		return dataMeta{}, err
	}
	var env struct {
		Data map[string]any `json:"data"`
		Meta map[string]any `json:"meta"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &env); err != nil {
		return dataMeta{}, err
	}
	return dataMeta{env.Data, env.Meta}, nil
}
