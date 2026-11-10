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

func TestHelmReadOnly(t *testing.T) {
	invHome(t)
	cfg := map[string]any{"replicas": 3, "image": map[string]any{"tag": "v2"}, "db": map[string]any{"password": "s3cret-pw"}}
	helmLab(t, "prod", http.StatusOK,
		helmSecret(t, "shop", "api", 1, "superseded", "api", "1.0.0", "1.0", map[string]any{"replicas": 2}),
		helmSecret(t, "shop", "api", 2, "deployed", "api", "1.1.0", "1.1", cfg),
		helmSecret(t, "ops", "grafana", 1, "deployed", "grafana", "8.5.0", "11.3.0", nil))

	d := mustRun(t, "cluster", "helm", "ls", "prod", "-A")
	rels := d["releases"].([]any)
	if len(rels) != 2 {
		t.Fatalf("releases: %v", d)
	}
	api := rels[1].(map[string]any) // ops/grafana sorts first
	if api["name"] != "api" || api["revision"].(float64) != 2 || api["status"] != "deployed" || api["chart"] != "api-1.1.0" || api["app_version"] != "1.1" {
		t.Errorf("newest revision of api: %v", api)
	}
	if d := mustRun(t, "cluster", "helm", "ls", "prod"); d["count"].(float64) != 1 || d["namespace"] != "shop" {
		t.Errorf("the context's namespace: %v", d)
	}

	st := mustRun(t, "cluster", "helm", "status", "prod", "api")
	if st["revision"].(float64) != 2 || st["notes"] != "visit https://api.example.com" || st["chart"] != "api-1.1.0" {
		t.Errorf("status: %v", st)
	}
	if st := mustRun(t, "cluster", "helm", "status", "prod", "api", "--revision", "1"); st["status"] != "superseded" {
		t.Errorf("--revision 1: %v", st)
	}
	wantCode(t, "HELM_REVISION_NOT_FOUND", "cluster", "helm", "status", "prod", "api", "--revision", "9")
	wantCode(t, "HELM_RELEASE_NOT_FOUND", "cluster", "helm", "status", "prod", "nope")

	h := mustRun(t, "cluster", "helm", "history", "prod", "api")
	if revs := h["revisions"].([]any); len(revs) != 2 || revs[0].(map[string]any)["revision"].(float64) != 1 {
		t.Errorf("history, oldest first: %v", h)
	}

	v := mustRun(t, "cluster", "helm", "values", "prod", "api")["values"].(map[string]any)
	if v["replicas"].(float64) != 3 || v["image"].(map[string]any)["pullPolicy"] != nil {
		t.Errorf("values are the user's only: %v", v)
	}
	all := mustRun(t, "cluster", "helm", "values", "prod", "api", "--all")["values"].(map[string]any)
	if img := all["image"].(map[string]any); img["tag"] != "v2" || img["pullPolicy"] != "IfNotPresent" || all["replicas"].(float64) != 3 {
		t.Errorf("--all merges the chart's defaults under them: %v", all)
	}

	t.Setenv("KOMANDO_AGENT", "1") // an agent does not see a password in values
	b, _ := json.Marshal(mustRun(t, "cluster", "helm", "values", "prod", "api"))
	if strings.Contains(string(b), "s3cret-pw") {
		t.Errorf("values show a password to an agent: %s", b)
	}
}

func TestClusterReadsManyClusters(t *testing.T) {
	invHome(t)
	helmLab(t, "eu", http.StatusOK, helmSecret(t, "shop", "api", 1, "deployed", "api", "1.0.0", "1.0", nil))
	helmLab(t, "us", http.StatusOK, helmSecret(t, "shop", "api", 3, "failed", "api", "1.2.0", "1.2", nil))
	mustRun(t, "group", "add", "prod", "eu,us")

	d := mustRun(t, "cluster", "helm", "ls", "@prod")
	res := d["results"].([]any)
	if len(res) != 2 || d["summary"].(map[string]any)["ok"].(float64) != 2 {
		t.Fatalf("two clusters: %v", d)
	}
	for i, want := range []string{"eu", "us"} {
		r := res[i].(map[string]any)
		if r["cluster"] != want || r["engine"] != "k8s" || r["ok"] != true || r["data"].(map[string]any)["count"].(float64) != 1 {
			t.Errorf("row %d: %v", i, r)
		}
	}

	helmLab(t, "ap", http.StatusForbidden)
	mustRun(t, "group", "add", "prod", "ap")
	d, e := invRun(t, "cluster", "helm", "ls", "@prod")
	if e == nil || e.Code != "PARTIAL_FAILURE" || !strings.Contains(e.Message, "ap") {
		t.Fatalf("one cluster refuses: %+v", e)
	}
	if d != nil {
		for _, r := range d["results"].([]any) {
			if r := r.(map[string]any); r["cluster"] == "ap" && (r["ok"] != false || r["error"].(map[string]any)["code"] != "K8S_FORBIDDEN") {
				t.Errorf("ap row: %v", r)
			}
		}
	}

	// one cluster: its own output, not a list
	if d := mustRun(t, "cluster", "helm", "ls", "eu"); d["results"] != nil || d["count"].(float64) != 1 {
		t.Errorf("one cluster: %v", d)
	}
	// a rollout and the commands that change a cluster stay on one cluster
	wantCode(t, "USAGE", "cluster", "status", "@prod", "deployment/api")
	wantCode(t, "USAGE", "cluster", "restart", "@prod", "deployment/api")
}

func TestClusterManyText(t *testing.T) {
	m := clusterMany{Results: []clusterRow{
		{Cluster: "eu", Engine: "k8s", OK: true, Data: helmList{"releases": []map[string]any{{"name": "api", "namespace": "shop", "revision": 1, "status": "deployed", "chart": "api-1.0.0", "app_version": "1.0", "updated": "now"}}}},
		{Cluster: "ap", Engine: "k8s", Error: &out.Error{Code: "K8S_FORBIDDEN", Message: "no", Hint: "ask for access"}},
	}, Summary: clusterSummary{Total: 2, OK: 1, Failed: 1}}
	got := m.Text()
	for _, want := range []string{"● eu (k8s)  ok\n", "  NAME", "  api ", "● ap (k8s)  FAILED\n", "  K8S_FORBIDDEN: no\n", "  hint: ask for access\n", "1 ok, 1 failed"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}
