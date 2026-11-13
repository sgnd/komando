package cli

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/kube"
)

// Verbs that only read.

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
			d, err := describeObject(r.ctx, r.k, r.conn, kr.r, meta(o, "name"), cmp.Or(meta(o, "namespace"), r.space(kr.r)))
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

// maxFollowBytes caps a followed log kept in memory (runKctlLive without a
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
			fmt.Fprintf(&r.stdout, "%s\n", cmp.Or(str(res["message"]), fmt.Sprintf("%s %q successfully rolled out", kindLower(kr.r), name)))
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
				rows = append(rows, []string{strconv.Itoa(rsRevision(s)), cmp.Or(annotation(s, "kubernetes.io/change-cause"), "<none>")})
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
