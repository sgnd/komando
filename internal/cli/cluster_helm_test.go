package cli

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// helmSecret stores a release the way Helm 3 does: JSON, gzipped, base64,
// in a Secret's data (which the API gives as base64 again).
func helmSecret(t *testing.T, ns, name string, rev int, status, chart, chartVer, app string, config map[string]any) map[string]any {
	t.Helper()
	rel := map[string]any{"name": name, "namespace": ns, "version": rev,
		"info":   map[string]any{"status": status, "last_deployed": "2026-11-0" + string(rune('0'+rev)) + "T10:00:00Z", "description": "Upgrade complete", "notes": "visit https://" + name + ".example.com"},
		"chart":  map[string]any{"metadata": map[string]any{"name": chart, "version": chartVer, "appVersion": app}, "values": map[string]any{"replicas": 1, "image": map[string]any{"tag": "latest", "pullPolicy": "IfNotPresent"}}},
		"config": config}
	j, _ := json.Marshal(rel)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(j)
	zw.Close()
	helm := base64.StdEncoding.EncodeToString(gz.Bytes())
	return map[string]any{
		"metadata": map[string]any{"name": "sh.helm.release.v1." + name + ".v" + string(rune('0'+rev)), "namespace": ns,
			"labels": map[string]any{"name": name, "owner": "helm", "status": status, "version": string(rune('0' + rev))}},
		"type": "helm.sh/release.v1",
		"data": map[string]any{"release": base64.StdEncoding.EncodeToString([]byte(helm))}}
}

// helmLab is a cluster API that holds Helm release Secrets; status other
// than 200 refuses every request with it.
func helmLab(t *testing.T, ctxName string, status int, secrets ...map[string]any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			io.WriteString(w, `{"reason":"Forbidden","message":"secrets is forbidden"}`)
			return
		}
		if r.URL.Query().Get("labelSelector") == "" || !strings.HasPrefix(r.URL.Query().Get("labelSelector"), "owner=helm") {
			t.Errorf("unexpected request %s", r.URL)
		}
		items := []any{}
		if strings.HasSuffix(r.URL.Path, "/secrets") {
			want := strings.TrimPrefix(r.URL.Query().Get("labelSelector"), "owner=helm,name=")
			for _, s := range secrets {
				md := s["metadata"].(map[string]any)
				inNS := !strings.Contains(r.URL.Path, "/namespaces/") || strings.Contains(r.URL.Path, "/namespaces/"+md["namespace"].(string)+"/")
				named := want == r.URL.Query().Get("labelSelector") || md["labels"].(map[string]any)["name"] == want
				if inNS && named {
					items = append(items, s)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	t.Cleanup(srv.Close)
	kc := "apiVersion: v1\nkind: Config\ncurrent-context: " + ctxName + "\nclusters:\n- name: c\n  cluster:\n    server: " + srv.URL +
		"\nusers:\n- name: u\n  user:\n    token: test-token-abcdef\ncontexts:\n- name: " + ctxName + "\n  context:\n    cluster: c\n    user: u\n    namespace: shop\n"
	p := filepath.Join(t.TempDir(), ctxName+".yaml")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "import", "kubeconfig", p)
	return srv.URL
}

// helmResult runs a helm snippet through `recipe run` and returns its result.
func helmResult(t *testing.T, args ...string) (map[string]any, *out.Error) {
	t.Helper()
	raw, e := snippetData(t, args...)
	var d struct {
		Result map[string]any `json:"result"`
	}
	_ = json.Unmarshal(raw, &d)
	return d.Result, e
}

// The helm reads stay after `cluster helm` goes: two snippets decode the
// release Secrets (row C631).
func TestHelmSnippets(t *testing.T) {
	invHome(t)
	withSnippets(t, helmSnippets()...)
	cfg := map[string]any{"replicas": 3, "image": map[string]any{"tag": "v2"}, "db": map[string]any{"password": "s3cret-pw"}}
	helmLab(t, "prod", http.StatusOK,
		helmSecret(t, "shop", "api", 1, "superseded", "api", "1.0.0", "1.0", map[string]any{"replicas": 2}),
		helmSecret(t, "shop", "api", 2, "deployed", "api", "1.1.0", "1.1", cfg),
		helmSecret(t, "ops", "grafana", 1, "deployed", "grafana", "8.5.0", "11.3.0", nil))

	d, e := helmResult(t, "helm-list", "prod")
	if e != nil {
		t.Fatalf("helm-list: %v", e)
	}
	rels := d["releases"].([]any)
	if len(rels) != 2 || d["count"].(float64) != 2 {
		t.Fatalf("every namespace by default: %v", d)
	}
	api := rels[1].(map[string]any) // ops/grafana sorts first
	if api["name"] != "api" || api["revision"].(float64) != 2 || api["status"] != "deployed" || api["chart"] != "api-1.1.0" || api["app_version"] != "1.1" {
		t.Errorf("newest revision of api: %v", api)
	}
	if d, _ := helmResult(t, "helm-list", "prod", "--var", "namespace=shop"); d["count"].(float64) != 1 || d["namespace"] != "shop" {
		t.Errorf("one namespace: %v", d)
	}

	r, e := helmResult(t, "helm-release", "prod", "--var", "release=api", "--var", "namespace=shop")
	if e != nil {
		t.Fatalf("helm-release: %v", e)
	}
	if r["revision"].(float64) != 2 || r["notes"] != "visit https://api.example.com" || r["chart"] != "api-1.1.0" || r["status"] != "deployed" {
		t.Errorf("the newest revision: %v", r)
	}
	if revs := r["history"].([]any); len(revs) != 2 || revs[0].(map[string]any)["revision"].(float64) != 1 {
		t.Errorf("history, oldest first: %v", r["history"])
	}
	v := r["values"].(map[string]any)
	if v["replicas"].(float64) != 3 || v["image"].(map[string]any)["pullPolicy"] != nil {
		t.Errorf("values are the user's only: %v", v)
	}
	if img := r["values_all"].(map[string]any)["image"].(map[string]any); img["tag"] != "v2" || img["pullPolicy"] != "IfNotPresent" {
		t.Errorf("values_all merges the chart's defaults under them: %v", r["values_all"])
	}
	if r, _ := helmResult(t, "helm-release", "prod", "--var", "release=api", "--var", "namespace=shop", "--var", "revision=1"); r["status"] != "superseded" {
		t.Errorf("revision 1: %v", r)
	}
	if _, e := helmResult(t, "helm-release", "prod", "--var", "release=api", "--var", "namespace=shop", "--var", "revision=9"); e == nil || e.Code != "HELM_REVISION_NOT_FOUND" {
		t.Errorf("revision 9: %v", e)
	}
	if _, e := helmResult(t, "helm-release", "prod", "--var", "release=nope", "--var", "namespace=shop"); e == nil || e.Code != "HELM_RELEASE_NOT_FOUND" {
		t.Errorf("no such release: %v", e)
	}
	// a name that is not a Kubernetes name never reaches the label selector
	if _, e := helmResult(t, "helm-release", "prod", "--var", "release=api,owner!=helm"); e == nil || e.Code == "HELM_RELEASE_NOT_FOUND" {
		t.Errorf("a release value that is a selector: %v", e)
	}

	setCallerEnv(t, "KOMANDO_AGENT", "1") // an agent does not see a password in values
	raw, _ := snippetData(t, "helm-release", "prod", "--var", "release=api", "--var", "namespace=shop")
	if strings.Contains(string(raw), "s3cret-pw") {
		t.Errorf("values show a password to an agent: %s", raw)
	}
}

// A Forbidden answer names the Secrets the kubeconfig's user may not list.
func TestHelmSnippetForbidden(t *testing.T) {
	invHome(t)
	withSnippets(t, helmSnippets()...)
	helmLab(t, "ap", http.StatusForbidden)
	if _, e := helmResult(t, "helm-list", "ap"); e == nil || e.Code != "K8S_FORBIDDEN" {
		t.Errorf("a refused list: %v", e)
	}
}
