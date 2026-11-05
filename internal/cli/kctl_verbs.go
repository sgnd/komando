package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// ---- reading ---------------------------------------------------------------

func (r *kctlRun) describe() error {
	refs, err := r.refs(r.a.pos)
	if err != nil {
		return err
	}
	first := true
	for _, kr := range refs {
		objs, err := r.getObjects(kr)
		if err != nil {
			return err
		}
		for _, o := range objs {
			d, err := describeObject(r.ctx, r.k, r.conn, kr.r, meta(o, "name"), firstNonEmpty(meta(o, "namespace"), r.space(kr.r)))
			if err != nil {
				return err
			}
			if !first {
				r.stdout.WriteString("\n\n")
			}
			first = false
			r.stdout.WriteString(d.Text())
		}
	}
	return nil
}

func (r *kctlRun) logs() error {
	if len(r.a.pos) == 0 && r.a.val("selector") == "" {
		return kfail("expected POD or TYPE/NAME is a required argument for the logs command")
	}
	space := r.ns()
	ref := ""
	if len(r.a.pos) > 0 {
		ref = r.a.pos[0]
	}
	pods, err := logPods(r.ctx, r.k, space, ref, r.a.val("selector"))
	if err != nil {
		return err
	}
	q := url.Values{}
	if c := r.a.val("container"); c != "" {
		q.Set("container", c)
	}
	if t := r.a.val("tail"); t != "" {
		q.Set("tailLines", t)
	}
	if s := r.a.val("since"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return kfail("invalid argument %q for --since", s)
		}
		q.Set("sinceSeconds", strconv.Itoa(int(d.Seconds())))
	}
	if r.a.bools["previous"] {
		q.Set("previous", "true")
	}
	if r.a.bools["timestamps"] {
		q.Set("timestamps", "true")
	}
	if !strings.Contains(ref, "/") && r.a.val("selector") == "" {
		pods = pods[:1]
	} else if ref != "" && r.a.val("selector") == "" {
		pods = pods[:1] // kubectl reads one pod of a workload
	}
	if r.a.bools["follow"] {
		return r.follow(space, pods, q)
	}
	for _, p := range pods {
		path := podLogPath(space, p)
		b, err := r.k.Do(r.ctx, "GET", path, q, nil, "")
		if err != nil {
			return err
		}
		(&prefixWriter{w: &r.stdout, prefix: r.logPrefix(p)}).Write(b)
	}
	return nil
}

// maxFollowBytes caps a followed log kept in memory (runKctl without a
// live printer); cluster run prints the lines as they come instead.
var maxFollowBytes = 8 << 20

// follow reads every pod's new lines at once, as kubectl logs -f does,
// until the streams end or --timeout / Ctrl-C (a normal end). Lines go to
// r.live as they come; nothing piles up in memory.
func (r *kctlRun) follow(space string, pods []string, q url.Values) error {
	most := 5 // kubectl's --max-log-requests
	if v := r.a.val("max-log-requests"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return kfail("--max-log-requests must be 1 or more")
		}
		most = n
	}
	if len(pods) > most {
		return kfail("you are attempting to follow %d log streams, but maximum allowed concurrency is %d, use --max-log-requests to increase the limit", len(pods), most)
	}
	live := r.live
	if live == nil {
		held, cut := 0, false
		live = func(_, prefix, line string) {
			if held += len(prefix) + len(line) + 1; held <= maxFollowBytes {
				r.stdout.WriteString(prefix + line + "\n")
			} else if !cut {
				cut = true
				fmt.Fprintf(&r.stderr, "komando: the followed log passed %d MiB; later lines were dropped\n", maxFollowBytes>>20)
			}
		}
	}
	_, err := streamPods(r.ctx, r.k, space, pods, q, func(pod, line string) { live(pod, r.logPrefix(pod), line) })
	if err != nil && r.ctx.Err() == nil {
		return err
	}
	return nil // --timeout or Ctrl-C ends a follow normally
}

func (r *kctlRun) logPrefix(pod string) string {
	if r.a.bools["prefix"] {
		return "[pod/" + pod + "] "
	}
	return ""
}

type prefixWriter struct {
	w      io.Writer
	prefix string
	mid    bool
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	if p.prefix == "" {
		return p.w.Write(b)
	}
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if !p.mid {
			p.w.Write([]byte(p.prefix))
		}
		p.w.Write(line)
		p.mid = !bytes.HasSuffix(line, []byte("\n"))
	}
	return len(b), nil
}

func (r *kctlRun) events() error {
	space := r.ns()
	if r.a.bools["all-namespaces"] {
		space = ""
	}
	evs, err := clusterEvents(r.ctx, r.k, space, "", "", false, 500)
	if err != nil {
		return err
	}
	r.stdout.WriteString(eventList{"events": evs}.Text())
	return nil
}

func (r *kctlRun) version() error {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := r.k.Get(r.ctx, "/version", nil, &v); err != nil {
		return err
	}
	fmt.Fprintf(&r.stdout, "Client Version: komando %s\nServer Version: %s\n", Version, v.GitVersion)
	return nil
}

func (r *kctlRun) apiResources() error {
	list, err := r.k.Resources(r.ctx)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, rt := range list {
		if r.a.bools["namespaced"] && !rt.Namespaced {
			continue
		}
		if r.a.val("output") == "name" {
			fmt.Fprintln(&r.stdout, qualifiedPlural(rt))
			continue
		}
		rows = append(rows, []string{rt.Name, strings.Join(rt.ShortNames, ","), rt.APIVersion(), strconv.FormatBool(rt.Namespaced), rt.Kind})
	}
	if r.a.val("output") != "name" {
		r.stdout.WriteString(kubectlTable([]string{"NAME", "SHORTNAMES", "APIVERSION", "NAMESPACED", "KIND"}, rows, r.a.bools["no-headers"]))
	}
	return nil
}

func (r *kctlRun) apiVersions() error {
	list, err := r.k.Resources(r.ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var vs []string
	for _, rt := range list {
		if !seen[rt.APIVersion()] {
			seen[rt.APIVersion()] = true
			vs = append(vs, rt.APIVersion())
		}
	}
	sort.Strings(vs)
	r.stdout.WriteString(strings.Join(vs, "\n") + "\n")
	return nil
}

func (r *kctlRun) clusterInfo() error {
	fmt.Fprintf(&r.stdout, "Kubernetes control plane is running at %s\n", r.k.Base.String())
	var svcs struct {
		Items []map[string]any `json:"items"`
	}
	if err := r.k.Get(r.ctx, "/api/v1/namespaces/kube-system/services", url.Values{"labelSelector": {"kubernetes.io/cluster-service=true"}}, &svcs); err == nil {
		for _, s := range svcs.Items {
			n := meta(s, "name")
			fmt.Fprintf(&r.stdout, "%s is running at %s/api/v1/namespaces/kube-system/services/%s/proxy\n", n, r.k.Base.String(), n)
		}
	}
	return nil
}

func (r *kctlRun) top() error {
	if len(r.a.pos) == 0 {
		return kfail("top needs pods or nodes")
	}
	what := strings.ToLower(r.a.pos[0])
	path := ""
	switch what {
	case "pod", "pods", "po":
		space := r.ns()
		path = "/apis/metrics.k8s.io/v1beta1/namespaces/" + url.PathEscape(space) + "/pods"
		if r.a.bools["all-namespaces"] {
			path = "/apis/metrics.k8s.io/v1beta1/pods"
		}
	case "node", "nodes", "no":
		path = "/apis/metrics.k8s.io/v1beta1/nodes"
	default:
		return kfail("top works on pods and nodes")
	}
	var list struct {
		Items []struct {
			Metadata   struct{ Name, Namespace string }
			Usage      map[string]string
			Containers []struct{ Usage map[string]string }
		}
	}
	if err := r.k.Get(r.ctx, path, r.listQuery(), &list); err != nil {
		var ae *kube.APIError
		if errors.As(err, &ae) && ae.Code == 404 {
			return kfail("Metrics API not available")
		}
		return err
	}
	var rows [][]string
	for _, it := range list.Items {
		cpu, mem := int64(0), int64(0)
		usages := []map[string]string{it.Usage}
		if it.Usage == nil {
			usages = nil
			for _, c := range it.Containers {
				usages = append(usages, c.Usage)
			}
		}
		for _, u := range usages {
			cpu += milliCPU(u["cpu"])
			mem += bytesOf(u["memory"])
		}
		row := []string{it.Metadata.Name, strconv.FormatInt(cpu, 10) + "m", strconv.FormatInt(mem>>20, 10) + "Mi"}
		if r.a.bools["all-namespaces"] {
			row = append([]string{it.Metadata.Namespace}, row...)
		}
		rows = append(rows, row)
	}
	headers := []string{"NAME", "CPU(cores)", "MEMORY(bytes)"}
	if r.a.bools["all-namespaces"] {
		headers = append([]string{"NAMESPACE"}, headers...)
	}
	r.stdout.WriteString(kubectlTable(headers, rows, r.a.bools["no-headers"]))
	return nil
}

// milliCPU reads a CPU quantity ("250m", "1", "123456789n").
func milliCPU(q string) int64 {
	switch {
	case strings.HasSuffix(q, "n"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(q, "n"), 10, 64)
		return n / 1e6
	case strings.HasSuffix(q, "u"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(q, "u"), 10, 64)
		return n / 1e3
	case strings.HasSuffix(q, "m"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(q, "m"), 10, 64)
		return n
	}
	f, _ := strconv.ParseFloat(q, 64)
	return int64(f * 1000)
}

// bytesOf reads a memory quantity ("128Mi", "1Gi", "123456Ki", "1000").
func bytesOf(q string) int64 {
	for suf, mul := range map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "k": 1e3, "M": 1e6, "G": 1e9} {
		if strings.HasSuffix(q, suf) {
			n, _ := strconv.ParseInt(strings.TrimSuffix(q, suf), 10, 64)
			return n * mul
		}
	}
	n, _ := strconv.ParseInt(q, 10, 64)
	return n
}

func (r *kctlRun) auth(sub string) error {
	switch sub {
	case "can-i":
		if len(r.a.pos) < 3 {
			return kfail("you must specify two arguments: verb resource or a non-resource URL")
		}
		verb, res := r.a.pos[1], r.a.pos[2]
		attrs := map[string]any{"verb": verb}
		if strings.HasPrefix(res, "/") {
			body, _ := json.Marshal(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
				"spec": map[string]any{"nonResourceAttributes": map[string]any{"verb": verb, "path": res}}})
			return r.canI(body)
		}
		typ, name, _ := strings.Cut(res, "/")
		if rt, err := r.k.Resource(r.ctx, typ); err == nil {
			attrs["resource"], attrs["group"] = rt.Name, rt.Group()
		} else {
			attrs["resource"] = typ
		}
		if name != "" {
			attrs["name"] = name
		}
		if !r.a.bools["all-namespaces"] {
			attrs["namespace"] = r.ns()
		}
		body, _ := json.Marshal(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
			"spec": map[string]any{"resourceAttributes": attrs}})
		return r.canI(body)
	case "whoami":
		body := []byte(`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`)
		b, err := r.k.Do(r.ctx, "POST", "/apis/authentication.k8s.io/v1/selfsubjectreviews", nil, body, "application/json")
		if err != nil {
			return err
		}
		var res struct {
			Status struct {
				UserInfo struct {
					Username string   `json:"username"`
					UID      string   `json:"uid"`
					Groups   []string `json:"groups"`
				} `json:"userInfo"`
			} `json:"status"`
		}
		json.Unmarshal(b, &res)
		u := res.Status.UserInfo
		rows := [][]string{{"Username", u.Username}}
		if u.UID != "" {
			rows = append(rows, []string{"UID", u.UID})
		}
		rows = append(rows, []string{"Groups", "[" + strings.Join(u.Groups, " ") + "]"})
		r.stdout.WriteString(kubectlTable([]string{"ATTRIBUTE", "VALUE"}, rows, false))
		return nil
	}
	return kfail("auth supports can-i and whoami")
}

func (r *kctlRun) canI(body []byte) error {
	b, err := r.k.Do(r.ctx, "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", nil, body, "application/json")
	if err != nil {
		return err
	}
	var res struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	json.Unmarshal(b, &res)
	if res.Status.Allowed {
		r.stdout.WriteString("yes\n")
		return nil
	}
	r.stdout.WriteString("no\n")
	return &kctlError{msg: ""} // kubectl exits 1 for "no"
}

// wait --for=condition=X[=true] | --for=delete | --for=jsonpath='{...}'=VALUE
func (r *kctlRun) wait() error {
	cond := r.a.val("for")
	if cond == "" {
		return kfail("--for must be set")
	}
	timeout := 30 * time.Second
	if t := r.a.val("timeout"); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return kfail("invalid --timeout %q", t)
		}
		timeout = d
	}
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	refs, err := r.refs(r.a.pos)
	if err != nil {
		return err
	}
	for _, kr := range refs {
		objs, err := r.getObjects(kr)
		if err != nil && cond != "delete" {
			return err
		}
		names := kr.names
		if len(names) == 0 {
			for _, o := range objs {
				names = append(names, meta(o, "name"))
			}
		}
		if len(names) == 0 {
			return kfail("no matching resources found")
		}
		for _, n := range names {
			path := kr.r.ObjectPath(r.space(kr.r), n)
			err := pollUntil(ctx, time.Second, func() (bool, error) {
				var o map[string]any
				gerr := r.k.Get(ctx, path, nil, &o)
				var ae *kube.APIError
				if cond == "delete" {
					return errors.As(gerr, &ae) && ae.Code == 404, nil
				}
				if gerr != nil {
					return false, nil
				}
				return conditionMet(cond, o), nil
			})
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return kfail("timed out waiting for the condition on %s/%s", qualifiedPlural(kr.r), n)
				}
				return err
			}
			verb := "condition met"
			if cond == "delete" {
				verb = "deleted"
			}
			fmt.Fprintf(&r.stdout, "%s/%s %s\n", kindQual(kr.r), n, verb)
		}
	}
	return nil
}

func conditionMet(cond string, o map[string]any) bool {
	if c, ok := strings.CutPrefix(cond, "condition="); ok {
		name, want, has := strings.Cut(c, "=")
		if !has {
			want = "true"
		}
		st, _ := o["status"].(map[string]any)
		conds, _ := st["conditions"].([]any)
		for _, x := range conds {
			m, _ := x.(map[string]any)
			if strings.EqualFold(str(m["type"]), name) {
				return strings.EqualFold(str(m["status"]), want)
			}
		}
		return false
	}
	if c, ok := strings.CutPrefix(cond, "jsonpath="); ok {
		i := strings.LastIndex(c, "}=")
		if i < 0 {
			return false
		}
		expr, want := c[:i+1], strings.Trim(c[i+2:], `'"`)
		var probe kctlRun
		if probe.printFormat("jsonpath="+expr, o) != nil {
			return false
		}
		return strings.TrimSpace(probe.stdout.String()) == want
	}
	return false
}

func (r *kctlRun) rollout(sub string) error {
	if len(r.a.pos) < 2 {
		return kfail("rollout %s needs TYPE/NAME", sub)
	}
	refs, err := r.refs(r.a.pos[1:])
	if err != nil {
		return err
	}
	kr := refs[0]
	if len(kr.names) == 0 {
		return kfail("rollout %s needs TYPE/NAME", sub)
	}
	name, space := kr.names[0], r.space(kr.r)
	path := kr.r.ObjectPath(space, name)
	q := r.dryQuery()
	switch sub {
	case "status":
		wait := rolloutWait()
		if t := r.a.val("timeout"); t != "" {
			if d, err := time.ParseDuration(t); err == nil {
				wait = d
			}
		}
		res, err := waitRollout(r.ctx, r.k, kr.r, space, name, wait)
		if res != nil {
			fmt.Fprintf(&r.stdout, "%s\n", firstNonEmpty(str(res["message"]), fmt.Sprintf("%s %q successfully rolled out", kindLower(kr.r), name)))
		}
		return err
	case "restart":
		patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339))
		if _, err := r.k.Do(r.ctx, "PATCH", path, q, []byte(patch), "application/strategic-merge-patch+json"); err != nil {
			return notFound(err, kr.r, name)
		}
		fmt.Fprintf(&r.stdout, "%s/%s restarted%s\n", kindQual(kr.r), name, r.dryNote())
	case "pause", "resume":
		patch := fmt.Sprintf(`{"spec":{"paused":%v}}`, sub == "pause")
		if _, err := r.k.Do(r.ctx, "PATCH", path, q, []byte(patch), "application/merge-patch+json"); err != nil {
			return notFound(err, kr.r, name)
		}
		fmt.Fprintf(&r.stdout, "%s/%s %sd%s\n", kindQual(kr.r), name, strings.TrimSuffix(sub, "e"), r.dryNote())
	case "history", "undo":
		if kr.r.Kind != "Deployment" {
			return kfail("rollout %s works on deployments here", sub)
		}
		var d map[string]any
		if err := r.k.Get(r.ctx, path, nil, &d); err != nil {
			return notFound(err, kr.r, name)
		}
		sets, err := replicaSets(r.ctx, r.k, space, d)
		if err != nil {
			return err
		}
		if sub == "history" {
			fmt.Fprintf(&r.stdout, "%s/%s \n", kindQual(kr.r), name)
			var rows [][]string
			sort.Slice(sets, func(i, j int) bool { return rsRevision(sets[i]) < rsRevision(sets[j]) })
			for _, s := range sets {
				rows = append(rows, []string{strconv.Itoa(rsRevision(s)), firstNonEmpty(annotation(s, "kubernetes.io/change-cause"), "<none>")})
			}
			r.stdout.WriteString(kubectlTable([]string{"REVISION", "CHANGE-CAUSE"}, rows, false))
			return nil
		}
		target, err := pickRollback(sets, deployRevision(d))
		if want := r.a.val("to-revision"); want != "" {
			target = nil
			n, _ := strconv.Atoi(want)
			for _, s := range sets {
				if rsRevision(s) == n {
					target = s
				}
			}
			if target == nil {
				return kfail("unable to find specified revision %s in history", want)
			}
			err = nil
		}
		if err != nil {
			return kfail("%v", err)
		}
		spec, _ := target["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		if md, ok := tmpl["metadata"].(map[string]any); ok {
			if l, ok := md["labels"].(map[string]any); ok {
				delete(l, "pod-template-hash")
			}
		}
		body, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": tmpl}})
		if _, err := r.k.Do(r.ctx, "PATCH", path, q, body, "application/strategic-merge-patch+json"); err != nil {
			return err
		}
		fmt.Fprintf(&r.stdout, "%s/%s rolled back%s\n", kindQual(kr.r), name, r.dryNote())
	default:
		return kfail("rollout supports status, history, undo, restart, pause and resume")
	}
	return nil
}

func kindLower(rt kube.ResourceType) string { return strings.ToLower(rt.Kind) }

func annotation(o map[string]any, key string) string {
	md, _ := o["metadata"].(map[string]any)
	a, _ := md["annotations"].(map[string]any)
	return str(a[key])
}

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
		"spec":     map[string]any{"restartPolicy": firstNonEmpty(r.a.val("restart"), "Always"), "containers": []any{c}}})
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

// cp copies between this computer and a pod with tar in the container,
// as kubectl cp does (the container needs tar).
func (r *kctlRun) cp() error {
	if len(r.a.pos) != 2 {
		return kfail("cp needs SRC DST, one of them POD:PATH")
	}
	src, dst := r.a.pos[0], r.a.pos[1]
	podOf := func(s string) (string, string, bool) {
		if strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || !strings.Contains(s, ":") {
			return "", "", false
		}
		p, path, _ := strings.Cut(s, ":")
		if _, after, ok := strings.Cut(p, "/"); ok { // NAMESPACE/POD
			p = after
		}
		return p, path, true
	}
	c := r.a.val("container")
	if pod, rpath, ok := podOf(src); ok {
		var tarball bytes.Buffer
		var errb bytes.Buffer
		rpath = path.Clean(rpath) // "/data/" is /data, "/x/.." is /
		dir, base := path.Dir(rpath), path.Base(rpath)
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "cf", "-", "-C", dir, base}, Stdout: &tarball, Stderr: &errb})
		if err != nil {
			return kfail("%s %s", strings.TrimSpace(errb.String()), err)
		}
		return untarTo(tarball.Bytes(), dst, base)
	}
	if pod, rpath, ok := podOf(dst); ok {
		var tarball bytes.Buffer
		if err := tarFrom(src, path.Base(rpath), &tarball); err != nil {
			return kwrap(err)
		}
		var errb bytes.Buffer
		err := r.k.Exec(r.ctx, kube.ExecOptions{Namespace: r.ns(), Pod: pod, Container: c, Command: []string{"tar", "xf", "-", "-C", path.Dir(rpath)},
			Stdin: &tarball, Stderr: &errb})
		if err != nil {
			return kfail("%s %s", strings.TrimSpace(errb.String()), err)
		}
		return nil
	}
	return kfail("one of SRC or DST must be POD:PATH")
}

// untarTo writes the tar stream (made by tar in the container, so the
// container picks every name in it) under dst; base is the copied name, so
// a single file can land at dst itself. Every entry must be base or lie
// under it, and land inside dst: one that does not is refused before
// anything is written, as is one inside a .git folder. Links and devices
// are skipped, like kubectl cp; a file gets the tar's mode without setuid,
// setgid or world-write.
func untarTo(tarball []byte, dst, base string) error {
	root, err := filepath.Abs(dst)
	if err != nil {
		return kfail("%v", err)
	}
	dstIsDir := false
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		dstIsDir = true
	}
	type entry struct {
		target string
		dir    bool
	}
	var plan []entry
	tr := tar.NewReader(bytes.NewReader(tarball))
	for first := true; ; first = false {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return kfail("%v", err)
		}
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeReg {
			plan = append(plan, entry{}) // skipped, but keeps the count for pass two
			continue
		}
		rel, ok := tarRel(h.Name, base)
		target := filepath.Join(root, filepath.FromSlash(rel))
		if ok && rel == "" && h.Typeflag == tar.TypeReg && first && dstIsDir {
			target = filepath.Join(root, base) // one file into a folder: keep its name
		}
		r, err := filepath.Rel(root, target)
		if !ok || err != nil || r != "." && !filepath.IsLocal(r) {
			return kfail("refusing %q: it would land outside %s", h.Name, dst)
		}
		if gitPath(r) { // git refuses to check out .git too: its config and hooks run commands
			return kfail("refusing %q: komando does not write into a .git folder", h.Name)
		}
		if link := symlinkOn(root, r); link != "" { // a link already there could lead out
			return kfail("refusing %q: %s is a symbolic link", h.Name, link)
		}
		plan = append(plan, entry{target: target, dir: h.Typeflag == tar.TypeDir})
	}
	tr = tar.NewReader(bytes.NewReader(tarball))
	for _, e := range plan {
		h, err := tr.Next()
		if err != nil {
			return kfail("%v", err)
		}
		switch {
		case e.target == "":
		case e.dir:
			if err := os.MkdirAll(e.target, 0o755); err != nil {
				return kfail("%v", err)
			}
		default:
			if err := os.MkdirAll(filepath.Dir(e.target), 0o755); err != nil {
				return kfail("%v", err)
			}
			mode := os.FileMode(h.Mode)&0o755 | 0o600 // as kubectl cp: never setuid, setgid or world-writable
			f, err := os.OpenFile(e.target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return kfail("%v", err)
			}
			if err := f.Chmod(mode); err != nil { // a file already there keeps no mode of its own
				f.Close()
				return kfail("%v", err)
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return kfail("%v", err)
			}
		}
	}
	return nil
}

// gitPath: rel has a .git part (any case: macOS and Windows ignore it).
func gitPath(rel string) bool {
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if strings.EqualFold(part, ".git") {
			return true
		}
	}
	return false
}

// localReadOK stops kctl from reading, for an AI agent, a file of this
// computer that it would send to the cluster (-f, --from-file, cp to a
// pod), where `get` would hand it back in full. It is guardLocalRead
// (komando's own folder always; a secret file unless the person allows
// --reveal) with kctl's error shape.
func localReadOK(p string) error {
	var stop *out.Error
	if err := guardLocalRead(p); errors.As(err, &stop) {
		return kstop(stop)
	} else if err != nil {
		return err
	}
	return nil
}

// symlinkOn is the first symbolic link on the way from root down to rel
// (root itself is the user's choice), or "".
func symlinkOn(root, rel string) string {
	if rel == "." {
		return ""
	}
	p := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if err != nil {
			return "" // not there yet: nothing below it is either
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return p
		}
	}
	return ""
}

// tarRel is where a tar entry goes, relative to the destination: "" for
// base itself, the rest of the name for what lies under base. ok is false
// for a name outside base or one that climbs out (.., an absolute path).
func tarRel(name, base string) (string, bool) {
	clean := path.Clean(name)
	var rel string
	switch {
	case base == "." || base == "/": // the whole folder was copied
		rel = strings.TrimPrefix(clean, "/")
		if rel == "." {
			rel = ""
		}
	case clean == base:
		rel = ""
	case strings.HasPrefix(clean, base+"/"):
		rel = clean[len(base)+1:]
	default:
		return "", false
	}
	return rel, rel == "" || filepath.IsLocal(filepath.FromSlash(rel))
}

func tarFrom(src, name string, w io.Writer) error {
	tw := tar.NewWriter(w)
	src = filepath.Clean(expandHome(src))
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = path.Join(name, filepath.ToSlash(rel))
		if rel == "." {
			h.Name = name
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			if err := localReadOK(p); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// debug adds an ephemeral container to a pod; open it with cluster shell.
func (r *kctlRun) debug() error {
	if len(r.a.pos) != 1 || r.a.val("image") == "" {
		return kfail("debug needs POD --image=IMAGE (and optionally --target=CONTAINER)")
	}
	pod := r.a.pos[0]
	name := firstNonEmpty(r.a.val("container"), fmt.Sprintf("debugger-%d", time.Now().Unix()%100000))
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
