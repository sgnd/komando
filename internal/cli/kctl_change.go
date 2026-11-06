package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/kube"
)

// ---- changing --------------------------------------------------------------

func (r *kctlRun) dryQuery() url.Values {
	q := url.Values{"fieldManager": {"komando"}}
	if g.dryRun {
		q.Set("dryRun", "All")
	}
	return q
}

func (r *kctlRun) dryNote() string {
	if g.dryRun {
		return " (server dry run)"
	}
	return ""
}

func (r *kctlRun) apply(diff bool) error {
	read := r.sendFiles
	if diff {
		read = r.readFiles // diff sends nothing that stays
	}
	docs, err := read()
	if err != nil {
		return err
	}
	saved := g.dryRun
	if diff {
		g.dryRun = true // diff is an apply the server only pretends to do
	}
	res, err := kubeApply(r.ctx, r.k, r.conn, docs, r.a.val("namespace"))
	g.dryRun = saved
	if err != nil {
		return err
	}
	a := res.(applyData)
	for _, o := range a.Objects {
		if diff {
			if o.Diff != "" {
				r.stdout.WriteString(o.Diff)
				if !strings.HasSuffix(o.Diff, "\n") {
					r.stdout.WriteString("\n")
				}
			}
			continue
		}
		fmt.Fprintf(&r.stdout, "%s %s%s\n", o.Object, firstNonEmpty(o.Action, "configured"), r.dryNote())
	}
	if diff {
		for _, o := range a.Objects {
			if o.Action != "none" && o.Action != "unchanged" {
				return &kctlError{msg: ""} // kubectl diff exits 1 when something differs
			}
		}
	}
	return nil
}

func (r *kctlRun) postObject(obj map[string]any) error {
	b, _ := json.Marshal(obj)
	apiVersion, kind := str(obj["apiVersion"]), str(obj["kind"])
	rt, err := r.k.ResourceFor(r.ctx, apiVersion, kind)
	if err != nil {
		return kfail("%v", err)
	}
	space := ""
	if rt.Namespaced {
		space = firstNonEmpty(meta(obj, "namespace"), r.ns())
	}
	if _, err := r.k.Do(r.ctx, "POST", rt.ObjectPath(space, ""), r.dryQuery(), b, "application/json"); err != nil {
		return err
	}
	fmt.Fprintf(&r.stdout, "%s/%s created%s\n", kindQual(rt), meta(obj, "name"), r.dryNote())
	return nil
}

func (r *kctlRun) create(sub string) error {
	if len(r.a.vals["filename"]) > 0 {
		docs, err := r.sendFiles()
		if err != nil {
			return err
		}
		for _, d := range docs {
			var obj map[string]any
			if err := json.Unmarshal(d.JSON, &obj); err != nil {
				return kfail("%v", err)
			}
			if err := r.postObject(obj); err != nil {
				return err
			}
		}
		return nil
	}
	if len(r.a.pos) < 2 && sub != "token" {
		return kfail("create %s needs a NAME", sub)
	}
	name := ""
	if len(r.a.pos) > 1 {
		name = r.a.pos[1]
	}
	ns := r.ns()
	md := map[string]any{"name": name, "namespace": ns}
	switch sub {
	case "namespace", "ns":
		return r.postObject(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": name}})
	case "serviceaccount", "sa":
		return r.postObject(map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": md})
	case "configmap", "cm":
		data, bin, err := r.fromSources()
		if err != nil {
			return err
		}
		obj := map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": md, "data": data}
		if len(bin) > 0 {
			obj["binaryData"] = bin
		}
		return r.postObject(obj)
	case "secret":
		if len(r.a.pos) < 3 {
			return kfail("create secret needs a type (generic, tls, docker-registry) and a NAME")
		}
		kind, name := strings.ToLower(r.a.pos[1]), r.a.pos[2]
		md["name"] = name
		obj := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": md}
		switch kind {
		case "generic":
			data, bin, err := r.fromSources()
			if err != nil {
				return err
			}
			enc := map[string]any{}
			for k, v := range data {
				enc[k] = base64.StdEncoding.EncodeToString([]byte(v.(string)))
			}
			for k, v := range bin {
				enc[k] = v
			}
			obj["type"], obj["data"] = firstNonEmpty(r.a.val("type"), "Opaque"), enc
		case "tls":
			crt, err1 := readLocalFile(r.a.val("cert"))
			key, err2 := readLocalFile(r.a.val("key"))
			if err := errors.Join(err1, err2); isSensitive(err) {
				return err
			}
			if err := errors.Join(err1, err2); err != nil {
				return kfail("create secret tls needs --cert and --key files: %v", err)
			}
			obj["type"] = "kubernetes.io/tls"
			obj["data"] = map[string]any{"tls.crt": base64.StdEncoding.EncodeToString(crt), "tls.key": base64.StdEncoding.EncodeToString(key)}
		case "docker-registry":
			server := firstNonEmpty(r.a.val("docker-server"), "https://index.docker.io/v1/")
			auth := base64.StdEncoding.EncodeToString([]byte(r.a.val("docker-username") + ":" + r.a.val("docker-password")))
			cfg, _ := json.Marshal(map[string]any{"auths": map[string]any{server: map[string]any{"username": r.a.val("docker-username"),
				"password": r.a.val("docker-password"), "email": r.a.val("docker-email"), "auth": auth}}})
			obj["type"] = "kubernetes.io/dockerconfigjson"
			obj["data"] = map[string]any{".dockerconfigjson": base64.StdEncoding.EncodeToString(cfg)}
		default:
			return kfail("create secret supports generic, tls and docker-registry")
		}
		return r.postObject(obj)
	case "deployment", "deploy":
		image := r.a.val("image")
		if image == "" {
			return kfail("required flag(s) \"image\" not set")
		}
		replicas, _ := strconv.Atoi(firstNonEmpty(r.a.val("replicas"), "1"))
		labels := map[string]any{"app": name}
		c := map[string]any{"name": containerName(image), "image": image}
		if p := r.a.val("port"); p != "" {
			n, _ := strconv.Atoi(p)
			c["ports"] = []any{map[string]any{"containerPort": n}}
		}
		if len(r.a.rest) > 0 {
			c["command"] = r.a.rest
		}
		md["labels"] = labels
		return r.postObject(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": md, "spec": map[string]any{
			"replicas": replicas, "selector": map[string]any{"matchLabels": labels},
			"template": map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"containers": []any{c}}}}})
	case "job":
		if from := r.a.val("from"); from != "" {
			t, cj, _ := strings.Cut(from, "/")
			if !oneOf(strings.ToLower(t), "cronjob", "cronjobs", "cj") {
				return kfail("--from must be cronjob/NAME")
			}
			var o map[string]any
			if err := r.k.Get(r.ctx, "/apis/batch/v1/namespaces/"+url.PathEscape(ns)+"/cronjobs/"+url.PathEscape(cj), nil, &o); err != nil {
				return err
			}
			spec, _ := o["spec"].(map[string]any)
			jt, _ := spec["jobTemplate"].(map[string]any)
			md["annotations"] = map[string]any{"cronjob.kubernetes.io/instantiate": "manual"}
			return r.postObject(map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": md, "spec": jt["spec"]})
		}
		image := r.a.val("image")
		if image == "" {
			return kfail("create job needs --image or --from=cronjob/NAME")
		}
		c := map[string]any{"name": name, "image": image}
		if len(r.a.rest) > 0 {
			c["command"] = r.a.rest
		}
		return r.postObject(map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": md, "spec": map[string]any{
			"template": map[string]any{"spec": map[string]any{"restartPolicy": "Never", "containers": []any{c}}}}})
	case "cronjob", "cj":
		image, sched := r.a.val("image"), r.a.val("schedule")
		if image == "" || sched == "" {
			return kfail("create cronjob needs --image and --schedule")
		}
		c := map[string]any{"name": name, "image": image}
		if len(r.a.rest) > 0 {
			c["command"] = r.a.rest
		}
		return r.postObject(map[string]any{"apiVersion": "batch/v1", "kind": "CronJob", "metadata": md, "spec": map[string]any{
			"schedule": sched, "jobTemplate": map[string]any{"spec": map[string]any{
				"template": map[string]any{"spec": map[string]any{"restartPolicy": "OnFailure", "containers": []any{c}}}}}}})
	case "service", "svc":
		if len(r.a.pos) < 3 {
			return kfail("create service needs a type (clusterip, nodeport, loadbalancer) and a NAME")
		}
		typ, name := strings.ToLower(r.a.pos[1]), r.a.pos[2]
		md["name"] = name
		var ports []any
		for _, p := range r.a.vals["tcp"] {
			port, target, _ := strings.Cut(p, ":")
			pn, _ := strconv.Atoi(port)
			tn, _ := strconv.Atoi(firstNonEmpty(target, port))
			ports = append(ports, map[string]any{"name": port + "-" + firstNonEmpty(target, port), "port": pn, "targetPort": tn, "protocol": "TCP"})
		}
		st := map[string]string{"clusterip": "ClusterIP", "nodeport": "NodePort", "loadbalancer": "LoadBalancer"}[typ]
		if st == "" {
			return kfail("create service supports clusterip, nodeport and loadbalancer")
		}
		return r.postObject(map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": md, "spec": map[string]any{
			"type": st, "selector": map[string]any{"app": name}, "ports": ports}})
	case "role", "clusterrole":
		var rules []any
		for _, res := range r.a.vals["resource"] {
			group, resource := "", res
			if i := strings.Index(res, "."); i > 0 {
				resource, group = res[:i], res[i+1:]
			} else if rt, err := r.k.Resource(r.ctx, res); err == nil {
				resource, group = rt.Name, rt.Group()
			}
			rule := map[string]any{"apiGroups": []any{group}, "resources": []any{resource}, "verbs": splitAll(r.a.vals["verb"])}
			if rn := r.a.vals["resource-name"]; len(rn) > 0 {
				rule["resourceNames"] = splitAll(rn)
			}
			rules = append(rules, rule)
		}
		kind := map[string]string{"role": "Role", "clusterrole": "ClusterRole"}[sub]
		if sub == "clusterrole" {
			delete(md, "namespace")
		}
		return r.postObject(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": md, "rules": rules})
	case "rolebinding", "clusterrolebinding":
		ref := map[string]any{"apiGroup": "rbac.authorization.k8s.io"}
		if cr := r.a.val("clusterrole"); cr != "" {
			ref["kind"], ref["name"] = "ClusterRole", cr
		} else if ro := r.a.val("role"); ro != "" && sub == "rolebinding" {
			ref["kind"], ref["name"] = "Role", ro
		} else {
			return kfail("exactly one of clusterrole or role must be specified")
		}
		var subjects []any
		for _, u := range r.a.vals["user-subject"] {
			subjects = append(subjects, map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": u})
		}
		for _, gname := range r.a.vals["group-subject"] {
			subjects = append(subjects, map[string]any{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": gname})
		}
		for _, sa := range r.a.vals["serviceaccount"] {
			sns, sname, ok := strings.Cut(sa, ":")
			if !ok {
				return kfail("serviceaccount must be <namespace>:<name>")
			}
			subjects = append(subjects, map[string]any{"kind": "ServiceAccount", "namespace": sns, "name": sname})
		}
		kind := map[string]string{"rolebinding": "RoleBinding", "clusterrolebinding": "ClusterRoleBinding"}[sub]
		if sub == "clusterrolebinding" {
			delete(md, "namespace")
		}
		return r.postObject(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": kind, "metadata": md, "roleRef": ref, "subjects": subjects})
	case "token":
		if len(r.a.pos) < 2 {
			return kfail("create token needs a service account NAME")
		}
		if g.dryRun {
			// a TokenRequest is not stored anywhere to dry-run: do not count
			// on the server to sign nothing, never send one
			return kfail("create token cannot be dry-run: it would make a real token")
		}
		spec := map[string]any{}
		if d := r.a.val("duration"); d != "" {
			dd, err := time.ParseDuration(d)
			if err != nil {
				return kfail("invalid --duration %q", d)
			}
			spec["expirationSeconds"] = int(dd.Seconds())
		}
		body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": spec})
		b, err := r.k.Do(r.ctx, "POST", "/api/v1/namespaces/"+url.PathEscape(ns)+"/serviceaccounts/"+url.PathEscape(r.a.pos[1])+"/token", nil, body, "application/json")
		if err != nil {
			return err
		}
		var tr struct {
			Status struct {
				Token string `json:"token"`
			} `json:"status"`
		}
		json.Unmarshal(b, &tr)
		r.stdout.WriteString(tr.Status.Token + "\n")
		return nil
	}
	return kfail("create supports -f FILE, namespace, serviceaccount, configmap, secret, deployment, job, cronjob, service, role, clusterrole, rolebinding, clusterrolebinding and token")
}

func splitAll(v []string) []any {
	var out []any
	for _, s := range v {
		for _, p := range strings.Split(s, ",") {
			out = append(out, p)
		}
	}
	return out
}

func containerName(image string) string {
	n := path.Base(image)
	n, _, _ = strings.Cut(n, ":")
	n, _, _ = strings.Cut(n, "@")
	return n
}

// fromSources reads --from-literal K=V and --from-file [K=]PATH.
func (r *kctlRun) fromSources() (map[string]any, map[string]any, error) {
	data, bin := map[string]any{}, map[string]any{}
	for _, l := range r.a.vals["from-literal"] {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, nil, kfail("invalid literal source %s, expected key=value", l)
		}
		data[k] = v
	}
	for _, f := range r.a.vals["from-file"] {
		k, p, ok := strings.Cut(f, "=")
		if !ok {
			p, k = f, filepath.Base(f)
		}
		if err := localReadOK(expandHome(p)); err != nil {
			return nil, nil, err
		}
		b, err := os.ReadFile(expandHome(p))
		if err != nil {
			if isSensitive(err) {
				return nil, nil, err
			}
			return nil, nil, kfail("%v", err)
		}
		if isText(b) {
			data[k] = string(b)
		} else {
			bin[k] = base64.StdEncoding.EncodeToString(b)
		}
	}
	return data, bin, nil
}

func isText(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return false
		}
	}
	return true
}

func (r *kctlRun) replace() error {
	docs, err := r.sendFiles()
	if err != nil {
		return err
	}
	for _, d := range docs {
		rt, err := r.k.ResourceFor(r.ctx, d.APIVersion, d.Kind)
		if err != nil {
			return kfail("%v", err)
		}
		space := ""
		if rt.Namespaced {
			space = firstNonEmpty(d.Namespace, r.ns())
		}
		var obj, cur map[string]any
		json.Unmarshal(d.JSON, &obj)
		if err := r.k.Get(r.ctx, rt.ObjectPath(space, d.Name), nil, &cur); err != nil {
			return notFound(err, rt, d.Name)
		}
		md, _ := obj["metadata"].(map[string]any)
		if md == nil {
			md = map[string]any{}
			obj["metadata"] = md
		}
		if md["resourceVersion"] == nil {
			md["resourceVersion"] = meta(cur, "resourceVersion")
		}
		b, _ := json.Marshal(obj)
		if _, err := r.k.Do(r.ctx, "PUT", rt.ObjectPath(space, d.Name), r.dryQuery(), b, "application/json"); err != nil {
			return err
		}
		fmt.Fprintf(&r.stdout, "%s/%s replaced%s\n", kindQual(rt), d.Name, r.dryNote())
	}
	return nil
}

func (r *kctlRun) delete() error {
	q := r.dryQuery()
	q.Del("fieldManager")
	if gp := r.a.val("grace-period"); gp != "" {
		q.Set("gracePeriodSeconds", gp)
	}
	if r.a.bools["force"] && r.a.val("grace-period") == "" {
		q.Set("gracePeriodSeconds", "0")
	}
	type target struct {
		rt          kube.ResourceType
		name, space string // space: "" for cluster-wide kinds
	}
	var targets []target
	if len(r.a.vals["filename"]) > 0 {
		docs, err := r.readFiles()
		if err != nil {
			return err
		}
		for _, d := range docs {
			rt, err := r.k.ResourceFor(r.ctx, d.APIVersion, d.Kind)
			if err != nil {
				return kfail("%v", err)
			}
			space := ""
			if rt.Namespaced {
				// the object's own namespace, as kubectl (and apply -f) use it
				if n := r.a.val("namespace"); n != "" && d.Namespace != "" && n != d.Namespace {
					return kfail("the namespace from the provided object %q does not match the namespace %q. You must pass '--namespace=%s' to perform this operation.", d.Namespace, n, d.Namespace)
				}
				space = firstNonEmpty(d.Namespace, r.ns())
			}
			targets = append(targets, target{rt, d.Name, space})
		}
	} else {
		refs, err := r.refs(r.a.pos)
		if err != nil {
			return err
		}
		for _, kr := range refs {
			if len(kr.names) == 0 {
				if r.a.val("selector") == "" && r.a.val("field-selector") == "" && !r.a.bools["all"] {
					return kfail("resource(s) were provided, but no name was specified")
				}
				objs, err := r.getObjects(kr)
				if err != nil {
					return err
				}
				for _, o := range objs {
					// with -A each object is in its own namespace
					targets = append(targets, target{kr.r, meta(o, "name"), firstNonEmpty(meta(o, "namespace"), r.space(kr.r))})
				}
				if len(objs) == 0 {
					r.stderr.WriteString("No resources found\n")
				}
			}
			for _, n := range kr.names {
				targets = append(targets, target{kr.r, n, r.space(kr.r)})
			}
		}
	}
	for _, t := range targets {
		if t.name == "" { // ObjectPath without a name is the whole collection
			return kfail("resource name may not be empty")
		}
	}
	for _, t := range targets {
		path := t.rt.ObjectPath(t.space, t.name)
		if _, err := r.k.Do(r.ctx, "DELETE", path, q, nil, ""); err != nil {
			var ae *kube.APIError
			if errors.As(err, &ae) && ae.Code == 404 && r.a.bools["ignore-not-found"] {
				continue
			}
			return notFound(err, t.rt, t.name)
		}
		from := ""
		if t.space != "" {
			from = " from " + t.space + " namespace" // which copy went, as kubectl says it
		}
		fmt.Fprintf(&r.stdout, "%s %q deleted%s%s\n", kindQual(t.rt), t.name, from, r.dryNote())
		if w, set := r.a.bools["wait"]; (!set || w) && !g.dryRun {
			// kubectl waits for the object to go; a finalizer can hold it,
			// so the wait ends after a minute (the delete itself is done)
			wctx, cancel := context.WithTimeout(r.ctx, time.Minute)
			_ = pollUntil(wctx, time.Second, func() (bool, error) {
				err := r.k.Get(r.ctx, path, nil, &map[string]any{})
				var ae *kube.APIError
				return errors.As(err, &ae) && ae.Code == 404, nil
			})
			cancel()
		}
	}
	return nil
}

func (r *kctlRun) one() (kube.ResourceType, string, error) {
	refs, err := r.refs(r.a.pos)
	if err != nil {
		return kube.ResourceType{}, "", err
	}
	if len(refs) != 1 || len(refs[0].names) != 1 {
		return kube.ResourceType{}, "", kfail("%s needs exactly one TYPE NAME (or TYPE/NAME)", r.a.verb)
	}
	if refs[0].names[0] == "" {
		return kube.ResourceType{}, "", kfail("resource name may not be empty")
	}
	return refs[0].r, refs[0].names[0], nil
}

func (r *kctlRun) patch() error {
	rt, name, err := r.one()
	if err != nil {
		return err
	}
	p := r.a.val("patch")
	if p == "" {
		return kfail("must specify --patch or -p")
	}
	if y, err := yamlToJSON([]byte(p)); err == nil {
		p = string(y)
	}
	ct := map[string]string{"": "application/strategic-merge-patch+json", "strategic": "application/strategic-merge-patch+json",
		"merge": "application/merge-patch+json", "json": "application/json-patch+json"}[r.a.val("type")]
	if ct == "" {
		return kfail("--type must be one of [json merge strategic]")
	}
	path := rt.ObjectPath(r.space(rt), name)
	if sub := r.a.val("subresource"); sub != "" {
		path += "/" + sub
	}
	if _, err := r.k.Do(r.ctx, "PATCH", path, r.dryQuery(), []byte(p), ct); err != nil {
		return notFound(err, rt, name)
	}
	fmt.Fprintf(&r.stdout, "%s/%s patched%s\n", kindQual(rt), name, r.dryNote())
	return nil
}

func yamlToJSON(b []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (r *kctlRun) labelAnnotate() error {
	field := map[string]string{"label": "labels", "annotate": "annotations"}[r.a.verb]
	var objPos, changes []string
	for _, p := range r.a.pos {
		if strings.Contains(p, "=") || strings.HasSuffix(p, "-") {
			changes = append(changes, p)
		} else {
			objPos = append(objPos, p)
		}
	}
	if len(changes) == 0 {
		return kfail("at least one %s update is required", strings.TrimSuffix(field, "s"))
	}
	refs, err := r.refs(objPos)
	if err != nil {
		return err
	}
	for _, kr := range refs {
		objs, err := r.getObjects(kr)
		if err != nil {
			return err
		}
		for _, o := range objs {
			md, _ := o["metadata"].(map[string]any)
			cur, _ := md[field].(map[string]any)
			set := map[string]any{}
			for _, c := range changes {
				if k, ok := strings.CutSuffix(c, "-"); ok && !strings.Contains(c, "=") {
					set[k] = nil
					continue
				}
				k, v, _ := strings.Cut(c, "=")
				if old, ok := cur[k]; ok && str(old) != v && !r.a.bools["overwrite"] {
					return kfail("'%s' already has a value (%s), and --overwrite is false", k, str(old))
				}
				set[k] = v
			}
			body, _ := json.Marshal(map[string]any{"metadata": map[string]any{field: set}})
			n := meta(o, "name")
			if _, err := r.k.Do(r.ctx, "PATCH", kr.r.ObjectPath(firstNonEmpty(meta(o, "namespace"), r.space(kr.r)), n), r.dryQuery(), body, "application/merge-patch+json"); err != nil {
				return err
			}
			fmt.Fprintf(&r.stdout, "%s/%s %s%s\n", kindQual(kr.r), n, map[string]string{"labels": "labeled", "annotations": "annotated"}[field], r.dryNote())
		}
	}
	return nil
}

func (r *kctlRun) scale() error {
	rt, name, err := r.one()
	if err != nil {
		return err
	}
	// the number as read, not the text: -0 or 00 must reach the server as
	// the 0 that `cluster run` rated (scalesToZero)
	n, err := strconv.Atoi(r.a.val("replicas"))
	if err != nil || n < 0 {
		return kfail("--replicas=COUNT is required, and COUNT must be greater than or equal to 0")
	}
	body := []byte(`{"spec":{"replicas":` + strconv.Itoa(n) + `}}`)
	if _, err := r.k.Do(r.ctx, "PATCH", rt.ObjectPath(r.space(rt), name)+"/scale", r.dryQuery(), body, "application/merge-patch+json"); err != nil {
		return notFound(err, rt, name)
	}
	fmt.Fprintf(&r.stdout, "%s/%s scaled%s\n", kindQual(rt), name, r.dryNote())
	return nil
}

func (r *kctlRun) set(sub string) error {
	if sub != "image" {
		return kfail("set supports image here; for other fields use `patch`")
	}
	if len(r.a.pos) < 3 {
		return kfail("set image needs TYPE/NAME CONTAINER=IMAGE ...")
	}
	r.a.pos = r.a.pos[1:]
	var objPos []string
	images := map[string]string{}
	for _, p := range r.a.pos {
		if c, img, ok := strings.Cut(p, "="); ok {
			images[c] = img
		} else {
			objPos = append(objPos, p)
		}
	}
	refs, err := r.refs(objPos)
	if err != nil {
		return err
	}
	for _, kr := range refs {
		for _, n := range kr.names {
			var o map[string]any
			if err := r.k.Get(r.ctx, kr.r.ObjectPath(r.space(kr.r), n), nil, &o); err != nil {
				return notFound(err, kr.r, n)
			}
			var cs []any
			for c, img := range images {
				if c == "*" {
					spec, _ := o["spec"].(map[string]any)
					tmpl, _ := spec["template"].(map[string]any)
					ps, _ := tmpl["spec"].(map[string]any)
					list, _ := ps["containers"].([]any)
					for _, x := range list {
						m, _ := x.(map[string]any)
						cs = append(cs, map[string]any{"name": m["name"], "image": img})
					}
					continue
				}
				cs = append(cs, map[string]any{"name": c, "image": img})
			}
			body, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": cs}}}})
			if _, err := r.k.Do(r.ctx, "PATCH", kr.r.ObjectPath(r.space(kr.r), n), r.dryQuery(), body, "application/strategic-merge-patch+json"); err != nil {
				return err
			}
			fmt.Fprintf(&r.stdout, "%s/%s image updated%s\n", kindQual(kr.r), n, r.dryNote())
		}
	}
	return nil
}
