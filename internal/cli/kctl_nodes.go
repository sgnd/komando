package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/kube"
)

func (r *kctlRun) cordon(on bool) error {
	if len(r.a.pos) == 0 {
		return kfail("%s needs a NODE", r.a.verb)
	}
	for _, n := range r.a.pos {
		body := []byte(fmt.Sprintf(`{"spec":{"unschedulable":%v}}`, on))
		if _, err := r.k.Do(r.ctx, "PATCH", "/api/v1/nodes/"+url.PathEscape(n), r.dryQuery(), body, "application/merge-patch+json"); err != nil {
			return notFound(err, kube.ResourceType{Name: "nodes"}, n)
		}
		fmt.Fprintf(&r.stdout, "node/%s %s%s\n", n, map[bool]string{true: "cordoned", false: "uncordoned"}[on], r.dryNote())
	}
	return nil
}

// drain cordons a node and evicts its pods (the Eviction API respects
// PodDisruptionBudgets), the way kubectl drain does.
func (r *kctlRun) drain() error {
	if len(r.a.pos) != 1 {
		return kfail("drain needs one NODE")
	}
	node := r.a.pos[0]
	if err := r.cordon(true); err != nil {
		return err
	}
	var pods struct {
		Items []map[string]any `json:"items"`
	}
	if err := r.k.Get(r.ctx, "/api/v1/pods", url.Values{"fieldSelector": {"spec.nodeName=" + node}}, &pods); err != nil {
		return err
	}
	var evict []map[string]any
	var problems []string
	for _, p := range pods.Items {
		md, _ := p["metadata"].(map[string]any)
		if _, mirror := md["annotations"].(map[string]any)["kubernetes.io/config.mirror"]; mirror {
			continue
		}
		owners, _ := md["ownerReferences"].([]any)
		kind := ""
		for _, o := range owners {
			if m, ok := o.(map[string]any); ok && m["controller"] == true {
				kind = str(m["kind"])
			}
		}
		name := str(md["namespace"]) + "/" + str(md["name"])
		if kind == "DaemonSet" {
			if !r.a.bools["ignore-daemonsets"] {
				problems = append(problems, "cannot delete DaemonSet-managed Pods (use --ignore-daemonsets to ignore): "+name)
			}
			continue
		}
		if kind == "" && !r.a.bools["force"] {
			problems = append(problems, "cannot delete Pods that declare no controller (use --force to override): "+name)
			continue
		}
		spec, _ := p["spec"].(map[string]any)
		vols, _ := spec["volumes"].([]any)
		for _, v := range vols {
			if m, ok := v.(map[string]any); ok && m["emptyDir"] != nil && !r.a.bools["delete-emptydir-data"] {
				problems = append(problems, "cannot delete Pods with local storage (use --delete-emptydir-data to override): "+name)
			}
		}
		evict = append(evict, p)
	}
	if len(problems) > 0 {
		return kfail("unable to drain node %q due to error: %s", node, strings.Join(problems, ", "))
	}
	for _, p := range evict {
		ns, n := meta(p, "namespace"), meta(p, "name")
		body, _ := json.Marshal(map[string]any{"apiVersion": "policy/v1", "kind": "Eviction", "metadata": map[string]any{"name": n, "namespace": ns}})
		err := pollUntil(r.ctx, 5*time.Second, func() (bool, error) {
			_, err := r.k.Do(r.ctx, "POST", "/api/v1/namespaces/"+url.PathEscape(ns)+"/pods/"+url.PathEscape(n)+"/eviction", r.dryQuery(), body, "application/json")
			var ae *kube.APIError
			if errors.As(err, &ae) && ae.Code == 429 {
				fmt.Fprintf(&r.stderr, "error when evicting pods/%q -n %q (will retry after 5s): %s\n", n, ns, ae.Message)
				return false, nil
			}
			if errors.As(err, &ae) && ae.Code == 404 {
				return true, nil
			}
			return err == nil, err
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(&r.stdout, "pod/%s evicted%s\n", n, r.dryNote())
	}
	fmt.Fprintf(&r.stdout, "node/%s drained%s\n", node, r.dryNote())
	return nil
}

func (r *kctlRun) taint() error {
	if len(r.a.pos) < 2 {
		return kfail("taint needs nodes NODE KEY=VALUE:EFFECT (or KEY:EFFECT-)")
	}
	pos := r.a.pos
	if oneOf(strings.ToLower(pos[0]), "node", "nodes", "no") {
		pos = pos[1:]
	}
	node, specs := pos[0], pos[1:]
	var o map[string]any
	if err := r.k.Get(r.ctx, "/api/v1/nodes/"+url.PathEscape(node), nil, &o); err != nil {
		return notFound(err, kube.ResourceType{Name: "nodes"}, node)
	}
	spec, _ := o["spec"].(map[string]any)
	list, _ := spec["taints"].([]any)
	for _, s := range specs {
		remove := strings.HasSuffix(s, "-")
		s = strings.TrimSuffix(s, "-")
		kv, effect, _ := strings.Cut(s, ":")
		key, val, _ := strings.Cut(kv, "=")
		var kept []any
		for _, t := range list {
			m, _ := t.(map[string]any)
			if str(m["key"]) == key && (effect == "" || str(m["effect"]) == effect) {
				continue
			}
			kept = append(kept, t)
		}
		list = kept
		if !remove {
			if effect == "" {
				return kfail("invalid taint spec: %s, must be key=value:effect", s)
			}
			t := map[string]any{"key": key, "effect": effect}
			if val != "" {
				t["value"] = val
			}
			list = append(list, t)
		}
	}
	if list == nil {
		list = []any{}
	}
	body, _ := json.Marshal(map[string]any{"spec": map[string]any{"taints": list}})
	if _, err := r.k.Do(r.ctx, "PATCH", "/api/v1/nodes/"+url.PathEscape(node), r.dryQuery(), body, "application/merge-patch+json"); err != nil {
		return err
	}
	fmt.Fprintf(&r.stdout, "node/%s modified%s\n", node, r.dryNote())
	return nil
}

func (r *kctlRun) runPod() error {
	if len(r.a.pos) == 0 || r.a.val("image") == "" {
		return kfail("run needs NAME --image=IMAGE")
	}
	if r.a.bools["tty"] || r.a.bools["stdin"] {
		return kfail("run -it opens a terminal: create the pod, then use `komando cluster shell`")
	}
	name := r.a.pos[0]
	c := map[string]any{"name": name, "image": r.a.val("image")}
	if len(r.a.rest) > 0 {
		c["args"] = r.a.rest
	}
	var env []any
	for _, e := range r.a.vals["env"] {
		k, v, _ := strings.Cut(e, "=")
		env = append(env, map[string]any{"name": k, "value": v})
	}
	if env != nil {
		c["env"] = env
	}
	if p := r.a.val("port"); p != "" {
		n, _ := strconv.Atoi(p)
		c["ports"] = []any{map[string]any{"containerPort": n}}
	}
	labels := map[string]any{"run": name}
	if l := r.a.val("labels"); l != "" {
		labels = map[string]any{}
		for _, kv := range strings.Split(l, ",") {
			k, v, _ := strings.Cut(kv, "=")
			labels[k] = v
		}
	}
	return r.postObject(map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": r.ns(), "labels": labels},
		"spec":     map[string]any{"restartPolicy": cmp.Or(r.a.val("restart"), "Always"), "containers": []any{c}}})
}

func (r *kctlRun) exec() error {
	if len(r.a.pos) == 0 || len(r.a.rest) == 0 {
		return kfail("exec needs POD -- COMMAND")
	}
	if r.a.bools["tty"] || r.a.bools["stdin"] {
		return kfail("exec -it opens a terminal: use `komando cluster shell TARGET %s`", r.a.pos[0])
	}
	pod, err := onePod(r.ctx, r.k, r.ns(), r.a.pos[0])
	if err != nil {
		return err
	}
	err = r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: r.a.val("container"), Command: r.a.rest, Stdout: &r.stdout, Stderr: &r.stderr})
	var ee *kube.ExitError
	if errors.As(err, &ee) {
		return &kctlError{msg: fmt.Sprintf("command terminated with exit code %d", ee.Code)}
	}
	return err
}

// debug adds an ephemeral container to a pod; open it with cluster shell.
func (r *kctlRun) debug() error {
	if len(r.a.pos) != 1 || r.a.val("image") == "" {
		return kfail("debug needs POD --image=IMAGE (and optionally --target=CONTAINER)")
	}
	pod := r.a.pos[0]
	name := cmp.Or(r.a.val("container"), fmt.Sprintf("debugger-%d", time.Now().Unix()%100000))
	ec := map[string]any{"name": name, "image": r.a.val("image"), "stdin": true, "tty": true}
	if t := r.a.val("target"); t != "" {
		ec["targetContainerName"] = t
	}
	if len(r.a.rest) > 0 {
		ec["command"] = r.a.rest
	}
	body, _ := json.Marshal(map[string]any{"spec": map[string]any{"ephemeralContainers": []any{ec}}})
	if _, err := r.k.Do(r.ctx, "PATCH", "/api/v1/namespaces/"+url.PathEscape(r.ns())+"/pods/"+url.PathEscape(pod)+"/ephemeralcontainers",
		r.dryQuery(), body, "application/strategic-merge-patch+json"); err != nil {
		return err
	}
	fmt.Fprintf(&r.stdout, "pod/%s: ephemeral container %s added%s; open it with `komando cluster shell TARGET %s -c %s -- sh`\n", pod, name, r.dryNote(), pod, name)
	return nil
}

func (r *kctlRun) certificate(sub string) error {
	if !oneOf(sub, "approve", "deny") || len(r.a.pos) < 2 {
		return kfail("certificate supports approve NAME and deny NAME")
	}
	for _, n := range r.a.pos[1:] {
		path := "/apis/certificates.k8s.io/v1/certificatesigningrequests/" + url.PathEscape(n)
		var csr map[string]any
		if err := r.k.Get(r.ctx, path, nil, &csr); err != nil {
			return err
		}
		st, _ := csr["status"].(map[string]any)
		if st == nil {
			st = map[string]any{}
			csr["status"] = st
		}
		conds, _ := st["conditions"].([]any)
		typ := map[string]string{"approve": "Approved", "deny": "Denied"}[sub]
		st["conditions"] = append(conds, map[string]any{"type": typ, "status": "True", "reason": "KomandoCertificate" + typ,
			"message": "This CSR was " + strings.ToLower(typ) + " by komando certificate " + sub, "lastUpdateTime": time.Now().UTC().Format(time.RFC3339)})
		b, _ := json.Marshal(csr)
		if _, err := r.k.Do(r.ctx, "PUT", path+"/approval", r.dryQuery(), b, "application/json"); err != nil {
			return err
		}
		fmt.Fprintf(&r.stdout, "certificatesigningrequest.certificates.k8s.io/%s %s\n", n, strings.ToLower(typ))
	}
	return nil
}

func (r *kctlRun) config(sub string) error {
	switch sub {
	case "current-context":
		fmt.Fprintln(&r.stdout, r.conn)
		return nil
	case "get-contexts":
		r.stdout.WriteString(kubectlTable([]string{"CURRENT", "NAME", "CLUSTER", "AUTHINFO", "NAMESPACE"},
			[][]string{{"*", r.conn, r.k.Base.Host, "", r.k.Namespace}}, false))
		return nil
	}
	return kfail("config supports current-context and get-contexts (komando keeps the kubeconfig in its vault)")
}

// readManifest reads a file, or the .yaml/.yml/.json files of a directory.
func readManifest(p string, recursive bool) ([]byte, error) {
	p = expandHome(p)
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		if err := localReadOK(p); err != nil {
			return nil, err
		}
		return os.ReadFile(p)
	}
	var all bytes.Buffer
	walk := func(f string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if f != p && !recursive {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := strings.ToLower(filepath.Ext(f)); ext == ".yaml" || ext == ".yml" || ext == ".json" {
			if err := localReadOK(f); err != nil {
				return err
			}
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			all.Write(b)
			all.WriteString("\n---\n")
		}
		return nil
	}
	if err := filepath.WalkDir(p, walk); err != nil {
		return nil, err
	}
	return all.Bytes(), nil
}
