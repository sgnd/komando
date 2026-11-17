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

// `cluster describe -o json` gives data.detail for a program: kind, name,
// namespace, status, created_at, labels, conditions and events, next to
// the fields it had before.
func TestClusterDescribeDetail(t *testing.T) {
	invHome(t)
	d := newDetailCluster(t)
	mustRun(t, "import", "kubeconfig", d.kubeconfig(t))

	res := mustRun(t, "cluster", "describe", "prod", "pod/api-1")
	for _, k := range []string{"conn", "object", "summary", "conditions", "containers", "events"} {
		if res[k] == nil {
			t.Errorf("describe lost %s: %v", k, res)
		}
	}
	if res["object"] != "pod/api-1" {
		t.Errorf("object stays the TYPE/NAME string: %v", res["object"])
	}
	det, _ := res["detail"].(map[string]any)
	want := map[string]any{"kind": "Pod", "name": "api-1", "namespace": "shop", "status": "Running", "created_at": "2026-11-01T08:00:00Z"}
	for k, v := range want {
		if det[k] != v {
			t.Errorf("detail.%s = %v, want %v", k, det[k], v)
		}
	}
	if l, _ := det["labels"].(map[string]any); l["app"] != "api" || l["tier"] != "web" {
		t.Errorf("labels: %v", det["labels"])
	}
	if cs, _ := det["conditions"].([]any); len(cs) != 2 || cs[0].(map[string]any)["type"] != "Ready" || cs[0].(map[string]any)["status"] != "True" {
		t.Errorf("conditions: %v", det["conditions"])
	}
	evs, _ := det["events"].([]any)
	if len(evs) != 2 {
		t.Fatalf("events: %v", det["events"])
	}
	last := evs[1].(map[string]any)
	if last["type"] != "Warning" || last["reason"] != "BackOff" || last["count"] != float64(4) || last["last_seen_at"] != "2026-11-14T09:59:59Z" || last["message"] == nil {
		t.Errorf("event: %v", last)
	}

	// a workload's status is how many of its pods are ready
	res = mustRun(t, "cluster", "describe", "prod", "deployment/api")
	det, _ = res["detail"].(map[string]any)
	if det["kind"] != "Deployment" || det["status"] != "ready 1/2" {
		t.Errorf("deployment detail: %v", det)
	}
	if cs, _ := det["conditions"].([]any); len(cs) != 1 || cs[0].(map[string]any)["reason"] != "MinimumReplicasUnavailable" {
		t.Errorf("deployment conditions: %v", det["conditions"])
	}
	if evs, _ := det["events"].([]any); len(evs) != 1 {
		t.Errorf("deployment events: %v", det["events"])
	}
}

// A Secret's values never show in `cluster describe`, for a person or an
// agent, in JSON or text: not base64, not decoded.
func TestClusterDescribeSecretHasNoData(t *testing.T) {
	invHome(t)
	d := newDetailCluster(t)
	mustRun(t, "import", "kubeconfig", d.kubeconfig(t))
	leaks := []string{detailSecretValue, base64.StdEncoding.EncodeToString([]byte(detailSecretValue))}
	check := func(who string) {
		res := mustRun(t, "cluster", "describe", "prod", "secret/app-db")
		det, _ := res["detail"].(map[string]any)
		if det["kind"] != "Secret" || det["name"] != "app-db" {
			t.Errorf("%s: secret detail: %v", who, det)
		}
		s, err := runCache(t, "-o", "text", "cluster", "describe", "prod", "secret/app-db")
		if err != nil {
			t.Fatalf("%s: text: %v", who, err)
		}
		for _, leak := range leaks {
			if b := jsonOf(res); strings.Contains(b, leak) {
				t.Errorf("%s: JSON shows the Secret's value: %s", who, b)
			}
			if strings.Contains(s, leak) {
				t.Errorf("%s: text shows the Secret's value: %s", who, s)
			}
		}
	}
	check("person")
	asAgent(t, false, false)
	check("agent")
}

// `cluster logs -o json` gives data.lines with each line's time and
// container, and truncated when the pod may have more than --limit lines;
// logs keeps its text as before.
func TestClusterLogsLines(t *testing.T) {
	invHome(t)
	d := newDetailCluster(t)
	mustRun(t, "import", "kubeconfig", d.kubeconfig(t))

	res := mustRun(t, "cluster", "logs", "prod", "api-1")
	if res["logs"] != "starting api\nlistening on :8080\nready\n" || res["pod"] != "api-1" {
		t.Errorf("logs text changed: %q", res["logs"])
	}
	lines, _ := res["lines"].([]any)
	if len(lines) != 3 || res["truncated"] != false {
		t.Fatalf("lines: %v truncated %v", res["lines"], res["truncated"])
	}
	first := lines[0].(map[string]any)
	if first["logged_at"] != "2026-11-14T10:00:00.123456789Z" || first["container"] != "api" || first["text"] != "starting api" || first["pod"] != "api-1" {
		t.Errorf("line: %v", first)
	}

	// --limit reached: the pod may have older lines
	d2, e := invRunMeta(t, "cluster", "logs", "prod", "api-1", "--limit", "2")
	if e != nil {
		t.Fatal(e)
	}
	if ls, _ := d2.data["lines"].([]any); len(ls) != 2 || d2.data["truncated"] != true || d2.meta["truncated"] != true {
		t.Errorf("--limit 2: %v meta %v", d2.data, d2.meta)
	}
	// --limit 0 is every line: no tailLines sent
	before := d.seen("tailLines")
	if res := mustRun(t, "cluster", "logs", "prod", "api-1", "--limit", "0"); res["truncated"] != false || len(res["lines"].([]any)) != 3 {
		t.Errorf("--limit 0: %v", res)
	}
	if d.seen("tailLines") != before {
		t.Errorf("--limit 0 sent tailLines: %v", d.reqs)
	}

	// --timestamps keeps the times in logs too
	res = mustRun(t, "cluster", "logs", "prod", "api-1", "--timestamps")
	if res["logs"] != detailLogs {
		t.Errorf("--timestamps logs: %q", res["logs"])
	}

	// -c names the container
	res = mustRun(t, "cluster", "logs", "prod", "api-2", "-c", "sidecar")
	if ls, _ := res["lines"].([]any); len(ls) != 3 || ls[0].(map[string]any)["container"] != "sidecar" {
		t.Errorf("-c sidecar: %v", res["lines"])
	}

	// several pods: each line names its pod; a pod that sends no logs is a line too
	res = mustRun(t, "cluster", "logs", "prod", "-l", "app=api")
	ls, _ := res["lines"].([]any)
	if len(ls) != 4 || ls[0].(map[string]any)["pod"] != "api-1" || ls[3].(map[string]any)["pod"] != "api-2" ||
		!strings.Contains(str(ls[3].(map[string]any)["text"]), "no logs") {
		t.Errorf("-l lines: %v", res["lines"])
	}
	if !strings.HasPrefix(str(res["logs"]), "[api-1] starting api\n") {
		t.Errorf("-l logs text changed: %q", res["logs"])
	}

	// text output is as before: no times asked from the API
	before = d.seen("timestamps=true")
	s, err := runCache(t, "-o", "text", "cluster", "logs", "prod", "api-1")
	if err != nil || s != "starting api\nlistening on :8080\nready\n" {
		t.Errorf("text: %v %q", err, s)
	}
	if d.seen("timestamps=true") != before {
		t.Errorf("text mode asked for timestamps")
	}
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

func TestSplitLogLines(t *testing.T) {
	raw := "2026-11-14T10:00:00Z one\nno time here\n2026-11-14T10:00:01.5Z  two spaces\n2026-11-14T10:00:02Z last, no newline"
	lines, text := splitLogLines(raw, "p", "c", false)
	if len(lines) != 4 {
		t.Fatalf("lines: %+v", lines)
	}
	if lines[0] != (logLine{LoggedAt: "2026-11-14T10:00:00Z", Pod: "p", Container: "c", Text: "one"}) {
		t.Errorf("first: %+v", lines[0])
	}
	if lines[1].LoggedAt != "" || lines[1].Text != "no time here" {
		t.Errorf("a line with no time keeps its text: %+v", lines[1])
	}
	if lines[2].Text != " two spaces" || lines[3].Text != "last, no newline" {
		t.Errorf("text kept as sent: %+v", lines[2:])
	}
	if text != "one\nno time here\n two spaces\nlast, no newline" {
		t.Errorf("text without times: %q", text)
	}
	if _, keep := splitLogLines(raw, "p", "c", true); keep != raw {
		t.Errorf("--timestamps keeps the text as sent: %q", keep)
	}
	if ls, text := splitLogLines("", "p", "c", false); ls != nil || text != "" {
		t.Errorf("empty: %v %q", ls, text)
	}
}
