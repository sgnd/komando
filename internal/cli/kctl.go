package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/jsonpath"

	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// kctl is komando's own implementation of the kubectl commands behind
// `cluster run`: it speaks to the API itself (no kubectl), writes what
// kubectl would print, and ends with kubectl's exit codes (0, or 1 with
// "error: ..." / "Error from server (...)" on stderr).

type kctlRun struct {
	k              *kube.Client
	conn           string
	stdout, stderr bytes.Buffer
	a              kargs
	ctx            context.Context
	// live, when set, gets the lines of a followed log (logs -f) as they
	// come, so they are printed at once instead of held until the end
	live func(pod, prefix, line string)
}

type kargs struct {
	verb  string
	pos   []string
	vals  map[string][]string
	bools map[string]bool
	rest  []string // after "--"
}

// kValueFlags are flags that take a value, by every spelling.
var kValueFlags = map[string]string{
	"-n": "namespace", "--namespace": "namespace", "-l": "selector", "--selector": "selector",
	"-o": "output", "--output": "output", "--field-selector": "field-selector", "-c": "container", "--container": "container",
	"--type": "type", "--patch": "patch", "--for": "for", "--timeout": "timeout", "--replicas": "replicas",
	"--image": "image", "--from-literal": "from-literal", "--from-file": "from-file", "--from": "from", "--sort-by": "sort-by",
	"--since": "since", "--tail": "tail", "--to-revision": "to-revision", "--grace-period": "grace-period",
	"--subresource": "subresource", "--port": "port", "--restart": "restart", "--env": "env", "--labels": "labels",
	"--target": "target", "--key": "key", "--cert": "cert", "--docker-server": "docker-server",
	"--docker-username": "docker-username", "--docker-password": "docker-password", "--docker-email": "docker-email",
	"--revision": "revision", "--schedule": "schedule", "--verb": "verb", "--resource": "resource",
	"--resource-name": "resource-name", "--role": "role", "--clusterrole": "clusterrole", "--user": "user-subject",
	"--group": "group-subject", "--serviceaccount": "serviceaccount", "--tcp": "tcp", "--duration": "duration",
	"--limit": "limit", "--chunk-size": "chunk-size", "--containers": "containers", "--profile": "profile",
	"--filename": "filename", "--overrides": "overrides", "--since-time": "since-time", "--max-log-requests": "max-log-requests",
}

var kBoolFlags = map[string]string{
	"-A": "all-namespaces", "--all-namespaces": "all-namespaces", "--all": "all", "-w": "watch", "--watch": "watch",
	"--watch-only": "watch-only", "--overwrite": "overwrite", "--force": "force", "--ignore-daemonsets": "ignore-daemonsets",
	"--delete-emptydir-data": "delete-emptydir-data", "--show-labels": "show-labels", "--no-headers": "no-headers",
	"-i": "stdin", "--stdin": "stdin", "-t": "tty", "--tty": "tty", "--previous": "previous", "--rm": "rm",
	"--wait": "wait", "-q": "quiet", "--quiet": "quiet", "-R": "recursive", "--recursive": "recursive",
	"--server-side": "server-side", "--timestamps": "timestamps", "--all-containers": "all-containers",
	"--follow": "follow", "--show-kind": "show-kind", "--list": "list", "--ignore-not-found": "ignore-not-found",
	"--prefix": "prefix", "--sort": "sort", "--no-headers=true": "no-headers", "--containers=true": "containers",
	"--disable-eviction": "disable-eviction", "--namespaced": "namespaced", "--recursive=true": "recursive",
	"--include-uninitialized": "include-uninitialized", "--use-protocol-buffers": "use-protocol-buffers",
}

func parseKargs(args []string) (kargs, error) {
	a := kargs{vals: map[string][]string{}, bools: map[string]bool{}}
	if len(args) == 0 {
		return a, errors.New("name a command, e.g. `-- get pods`")
	}
	a.verb = strings.ToLower(args[0])
	for i := 1; i < len(args); i++ {
		s := args[i]
		if s == "--" {
			a.rest = args[i+1:]
			break
		}
		if !strings.HasPrefix(s, "-") || s == "-" {
			a.pos = append(a.pos, s)
			continue
		}
		name, val, hasVal := strings.Cut(s, "=")
		// verb-specific short flags
		switch {
		case a.verb == "logs" && (name == "-f"):
			a.bools["follow"] = true
			continue
		case a.verb == "logs" && name == "-p":
			a.bools["previous"] = true
			continue
		case name == "-f" || name == "--filename":
			name = "--filename"
		case name == "-p" || name == "--patch":
			name = "--patch"
		case (a.verb == "exec" || a.verb == "run" || a.verb == "attach" || a.verb == "debug") && (name == "-it" || name == "-ti"):
			a.bools["stdin"], a.bools["tty"] = true, true
			continue
		}
		if key, ok := kValueFlags[name]; ok {
			if !hasVal {
				if len(name) == 2 && len(s) > 2 && !strings.Contains(s, "=") { // -oyaml, -nshop
					val, hasVal = s[2:], true
				} else if i+1 < len(args) {
					i++
					val, hasVal = args[i], true
				}
			}
			if !hasVal {
				return a, fmt.Errorf("flag needs an argument: %s", name)
			}
			a.vals[key] = append(a.vals[key], val)
			continue
		}
		if len(name) > 2 && name[1] != '-' { // -oyaml, -nshop, -lapp=x
			if key, ok := kValueFlags[name[:2]]; ok {
				v := s[2:]
				a.vals[key] = append(a.vals[key], v)
				continue
			}
		}
		if key, ok := kBoolFlags[name]; ok {
			if hasVal && val != "true" && val != "false" {
				return a, fmt.Errorf("invalid argument %q for %s: use true or false", val, name)
			}
			a.bools[key] = !hasVal || val == "true"
			continue
		}
		return a, fmt.Errorf("unknown flag: %s", name)
	}
	return a, nil
}

func (a kargs) val(key string) string {
	if v := a.vals[key]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

func (r *kctlRun) ns() string {
	return firstNonEmpty(r.a.val("namespace"), r.k.Namespace)
}

// kctlError ends a command with kubectl's exit code 1. stop, when set, is
// komando's own safety stop (with its code and hint), which `cluster run`
// returns as it is.
type kctlError struct {
	msg  string
	stop *out.Error
}

func (e *kctlError) Error() string { return e.msg }

func kfail(format string, a ...any) error {
	return &kctlError{msg: "error: " + fmt.Sprintf(format, a...)}
}

// kstop is a kctl error that is one of komando's safety stops.
func kstop(e *out.Error) error { return &kctlError{msg: "error: " + e.Message, stop: e} }

// kwrap keeps a kctlError (a safety stop) as it is, and words any other
// error as kubectl does.
func kwrap(err error) error {
	var ke *kctlError
	if errors.As(err, &ke) {
		return ke
	}
	return kfail("%v", err)
}

// runKctl runs one kubectl-style command and returns its exit code with
// what kubectl would have printed.
func runKctl(ctx context.Context, k *kube.Client, conn string, args []string) (code int, stdout, stderr string) {
	code, stdout, stderr, _ = runKctlLive(ctx, k, conn, args, nil)
	return code, stdout, stderr
}

// runKctlLive is runKctl that hands a followed log's lines to live as they
// come (nil: they go to stdout, up to maxFollowBytes). stop is the safety
// stop that ended the command before it sent anything, if one did.
func runKctlLive(ctx context.Context, k *kube.Client, conn string, args []string, live func(pod, prefix, line string)) (code int, stdout, stderr string, stop *out.Error) {
	r := &kctlRun{k: k, conn: conn, ctx: ctx, live: live}
	a, err := parseKargs(args)
	if err == nil {
		r.a = a
		err = r.dispatch()
	}
	if err != nil {
		var ke *kctlError
		var ae *kube.APIError
		switch {
		case errors.As(err, &ke):
			r.stderr.WriteString(ke.msg + "\n")
			stop = ke.stop
		case errors.As(err, &ae):
			r.stderr.WriteString(fmt.Sprintf("Error from server (%s): %s\n", strings.ReplaceAll(ae.Reason, " ", ""), ae.Message))
		case errors.Is(err, context.DeadlineExceeded):
			r.stderr.WriteString("error: timed out waiting for the condition\n")
		default:
			r.stderr.WriteString("error: " + err.Error() + "\n")
		}
		return 1, r.stdout.String(), r.stderr.String(), stop
	}
	return 0, r.stdout.String(), r.stderr.String(), nil
}

func (r *kctlRun) dispatch() error {
	sub := ""
	if len(r.a.pos) > 0 {
		sub = strings.ToLower(r.a.pos[0])
	}
	switch r.a.verb {
	case "get":
		return r.get()
	case "describe":
		return r.describe()
	case "logs", "log":
		return r.logs()
	case "events":
		return r.events()
	case "version":
		return r.version()
	case "api-resources":
		return r.apiResources()
	case "api-versions":
		return r.apiVersions()
	case "cluster-info":
		return r.clusterInfo()
	case "explain":
		return r.explain()
	case "top":
		return r.top()
	case "auth":
		return r.auth(sub)
	case "wait":
		return r.wait()
	case "rollout":
		return r.rollout(sub)
	case "apply":
		return r.apply(false)
	case "diff":
		return r.apply(true)
	case "create":
		return r.create(sub)
	case "replace":
		return r.replace()
	case "delete":
		return r.delete()
	case "patch":
		return r.patch()
	case "label", "annotate":
		return r.labelAnnotate()
	case "scale":
		return r.scale()
	case "set":
		return r.set(sub)
	case "cordon", "uncordon":
		return r.cordon(r.a.verb == "cordon")
	case "drain":
		return r.drain()
	case "taint":
		return r.taint()
	case "run":
		return r.runPod()
	case "exec":
		return r.exec()
	case "cp":
		return r.cp()
	case "debug":
		return r.debug()
	case "certificate":
		return r.certificate(sub)
	case "config":
		return r.config(sub)
	case "port-forward", "proxy", "attach":
		return kfail("%s is a session: use `komando cluster forward` (ports) or `komando cluster shell` (a terminal)", r.a.verb)
	case "edit":
		return kfail("edit opens an editor: use `komando cluster get TARGET TYPE NAME -o yaml`, change the file, then `cluster run --write -- apply -f FILE`")
	}
	return kfail("unknown command %q for komando's kubectl (see `komando cluster run --help`)", r.a.verb)
}

// ---- resources and objects ----------------------------------------------

type kref struct {
	r     kube.ResourceType
	names []string
}

// refs reads "TYPE NAME...", "TYPE/NAME ...", "TYPE1,TYPE2" from pos.
func (r *kctlRun) refs(pos []string) ([]kref, error) {
	if len(pos) == 0 {
		return nil, kfail("you must specify the type of resource to get")
	}
	var out []kref
	resolve := func(t string) ([]kube.ResourceType, error) {
		if strings.ToLower(t) == "all" {
			var list []kube.ResourceType
			for _, n := range []string{"pods", "services", "daemonsets", "deployments", "replicasets", "statefulsets", "horizontalpodautoscalers", "jobs", "cronjobs"} {
				if rt, err := r.k.Resource(r.ctx, n); err == nil {
					list = append(list, rt)
				}
			}
			return list, nil
		}
		rt, err := r.k.Resource(r.ctx, t)
		if err != nil {
			return nil, kfail("the server doesn't have a resource type %q", t)
		}
		return []kube.ResourceType{rt}, nil
	}
	if strings.Contains(pos[0], "/") {
		for _, p := range pos {
			t, n, ok := strings.Cut(p, "/")
			if !ok {
				return nil, kfail("there is no need to specify a resource type as a separate argument when passing arguments in resource/name form")
			}
			if n == "" {
				return nil, kfail("resource name may not be empty") // the API would read it as every object (deletecollection)
			}
			rts, err := resolve(t)
			if err != nil {
				return nil, err
			}
			out = append(out, kref{r: rts[0], names: []string{n}})
		}
		return out, nil
	}
	if slices.Contains(pos[1:], "") {
		return nil, kfail("resource name may not be empty")
	}
	for _, t := range strings.Split(pos[0], ",") {
		rts, err := resolve(t)
		if err != nil {
			return nil, err
		}
		for _, rt := range rts {
			out = append(out, kref{r: rt, names: pos[1:]})
		}
	}
	return out, nil
}

// space is the namespace for r: "" for cluster-wide kinds and with -A.
func (r *kctlRun) space(rt kube.ResourceType) string {
	if !rt.Namespaced || r.a.bools["all-namespaces"] {
		return ""
	}
	return r.ns()
}

func (r *kctlRun) listQuery() url.Values {
	q := url.Values{}
	if s := r.a.val("selector"); s != "" {
		q.Set("labelSelector", s)
	}
	if s := r.a.val("field-selector"); s != "" {
		q.Set("fieldSelector", s)
	}
	return q
}

// qualified is how kubectl names a kind in output: deployment.apps.
func kindQual(rt kube.ResourceType) string {
	k := strings.ToLower(rt.Kind)
	if g := rt.Group(); g != "" {
		return k + "." + g
	}
	return k
}

func (r *kctlRun) getObjects(kr kref) ([]map[string]any, error) {
	space := r.space(kr.r)
	if len(kr.names) == 0 {
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if err := r.k.Get(r.ctx, kr.r.ObjectPath(space, ""), r.listQuery(), &list); err != nil {
			return nil, err
		}
		for _, o := range list.Items {
			o["apiVersion"], o["kind"] = kr.r.APIVersion(), kr.r.Kind
		}
		return list.Items, nil
	}
	var objs []map[string]any
	for _, n := range kr.names {
		var o map[string]any
		if err := r.k.Get(r.ctx, kr.r.ObjectPath(space, n), nil, &o); err != nil {
			var ae *kube.APIError
			if errors.As(err, &ae) && ae.Code == 404 && r.a.bools["ignore-not-found"] {
				continue
			}
			return nil, notFound(err, kr.r, n)
		}
		objs = append(objs, o)
	}
	return objs, nil
}

// notFound words a 404 the way kubectl does.
func notFound(err error, rt kube.ResourceType, name string) error {
	var ae *kube.APIError
	if errors.As(err, &ae) && ae.Code == 404 {
		return &kube.APIError{Code: 404, Reason: "NotFound", Message: fmt.Sprintf("%s %q not found", qualifiedPlural(rt), name)}
	}
	return err
}

func qualifiedPlural(rt kube.ResourceType) string {
	if g := rt.Group(); g != "" {
		return rt.Name + "." + g
	}
	return rt.Name
}

// ---- get -------------------------------------------------------------------

func (r *kctlRun) get() error {
	refs, err := r.refs(r.a.pos)
	if err != nil {
		return err
	}
	format := r.a.val("output")
	switch {
	case format == "" || format == "wide":
		return r.getTables(refs, format == "wide")
	case format == "name":
		for _, kr := range refs {
			objs, err := r.getObjects(kr)
			if err != nil {
				return err
			}
			for _, o := range objs {
				fmt.Fprintf(&r.stdout, "%s/%s\n", kindQual(kr.r), meta(o, "name"))
			}
		}
		return r.watchAfter(refs)
	}
	var all []map[string]any
	for _, kr := range refs {
		objs, err := r.getObjects(kr)
		if err != nil {
			return err
		}
		for _, o := range objs {
			o["apiVersion"], o["kind"] = kr.r.APIVersion(), kr.r.Kind
			// an agent sees no Secret value or secret env value, even though
			// the whole object leaves here as one string of text
			maskObject(o)
			all = append(all, o)
		}
	}
	single := len(refs) == 1 && len(refs[0].names) == 1 && len(all) == 1
	var doc any = map[string]any{"apiVersion": "v1", "kind": "List", "items": all, "metadata": map[string]any{"resourceVersion": ""}}
	if single {
		doc = all[0]
	}
	return r.printFormat(format, doc)
}

func (r *kctlRun) printFormat(format string, doc any) error {
	switch {
	case format == "json":
		b, _ := json.MarshalIndent(doc, "", "    ")
		r.stdout.Write(append(b, '\n'))
	case format == "yaml":
		var y bytes.Buffer
		enc := yaml.NewEncoder(&y)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return err
		}
		r.stdout.Write(y.Bytes())
	case strings.HasPrefix(format, "jsonpath=") || strings.HasPrefix(format, "jsonpath-as-json="):
		expr := strings.SplitN(format, "=", 2)[1]
		jp := jsonpath.New("out").AllowMissingKeys(true)
		if strings.HasPrefix(format, "jsonpath-as-json") {
			jp.EnableJSONOutput(true)
		}
		if err := jp.Parse(expr); err != nil {
			return kfail("error parsing jsonpath %s, %v", expr, err)
		}
		// jsonpath works on plain JSON values
		b, _ := json.Marshal(doc)
		var v any
		json.Unmarshal(b, &v)
		if err := jp.Execute(&r.stdout, v); err != nil {
			return kfail("%v", err)
		}
	case strings.HasPrefix(format, "custom-columns="):
		return r.customColumns(strings.TrimPrefix(format, "custom-columns="), doc)
	default:
		return kfail("unable to match a printer suitable for the output format %q, allowed formats are: custom-columns,json,jsonpath,jsonpath-as-json,name,wide,yaml", format)
	}
	return nil
}

func (r *kctlRun) customColumns(spec string, doc any) error {
	type col struct {
		name string
		jp   *jsonpath.JSONPath
	}
	var cols []col
	for _, c := range strings.Split(spec, ",") {
		name, expr, ok := strings.Cut(c, ":")
		if !ok {
			return kfail("custom-columns format specified but no custom columns given")
		}
		if !strings.HasPrefix(expr, "{") {
			expr = "{" + expr + "}"
		}
		jp := jsonpath.New(name).AllowMissingKeys(true)
		if err := jp.Parse(expr); err != nil {
			return kfail("%v", err)
		}
		cols = append(cols, col{name, jp})
	}
	items := []any{doc}
	if m, ok := doc.(map[string]any); ok && m["kind"] == "List" {
		items = nil
		for _, o := range m["items"].([]map[string]any) {
			items = append(items, o)
		}
	}
	var rows [][]string
	for _, it := range items {
		b, _ := json.Marshal(it)
		var v any
		json.Unmarshal(b, &v)
		var row []string
		for _, c := range cols {
			var buf bytes.Buffer
			if err := c.jp.Execute(&buf, v); err != nil || buf.Len() == 0 {
				row = append(row, "<none>")
				continue
			}
			row = append(row, buf.String())
		}
		rows = append(rows, row)
	}
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.name
	}
	r.stdout.WriteString(kubectlTable(headers, rows, r.a.bools["no-headers"]))
	return nil
}

// getTables prints the server's tables, as kubectl does.
func (r *kctlRun) getTables(refs []kref, wide bool) error {
	many := len(refs) > 1
	printed := false
	for _, kr := range refs {
		space := r.space(kr.r)
		var tables []*kube.Table
		if len(kr.names) == 0 {
			t, err := r.k.Table(r.ctx, kr.r.ObjectPath(space, ""), r.listQuery())
			if err != nil {
				return err
			}
			tables = append(tables, t)
		} else {
			for _, n := range kr.names {
				t, err := r.k.Table(r.ctx, kr.r.ObjectPath(space, n), nil)
				if err != nil {
					return notFound(err, kr.r, n)
				}
				tables = append(tables, t)
			}
		}
		var headers []string
		var keep []int
		var rows [][]string
		for ti, t := range tables {
			if ti == 0 {
				for i, c := range t.ColumnDefinitions {
					if c.Priority == 0 || wide {
						keep = append(keep, i)
						headers = append(headers, strings.ToUpper(c.Name))
					}
				}
			}
			for _, row := range t.Rows {
				var cells []string
				if r.a.bools["all-namespaces"] && kr.r.Namespaced {
					cells = append(cells, row.Object.Metadata.Namespace)
				}
				for j, i := range keep {
					c := ""
					if i < len(row.Cells) {
						c = tableCell(row.Cells[i])
					}
					if j == 0 && many {
						c = kindQual(kr.r) + "/" + c
					}
					cells = append(cells, c)
				}
				if r.a.bools["show-labels"] {
					cells = append(cells, "<labels>")
				}
				rows = append(rows, cells)
			}
		}
		if len(rows) == 0 {
			continue
		}
		if r.a.bools["all-namespaces"] && kr.r.Namespaced {
			headers = append([]string{"NAMESPACE"}, headers...)
		}
		if r.a.bools["show-labels"] {
			headers = append(headers, "LABELS")
			if err := r.fillLabels(kr, rows); err != nil {
				return err
			}
		}
		if printed {
			r.stdout.WriteString("\n")
		}
		r.stdout.WriteString(kubectlTable(headers, rows, r.a.bools["no-headers"]))
		printed = true
	}
	if !printed && !r.a.bools["watch"] {
		if len(refs) == 1 && !refs[0].r.Namespaced || r.a.bools["all-namespaces"] {
			r.stderr.WriteString("No resources found\n")
		} else {
			r.stderr.WriteString("No resources found in " + r.ns() + " namespace.\n")
		}
	}
	return r.watchAfter(refs)
}

// fillLabels replaces the "<labels>" cells with each object's labels.
func (r *kctlRun) fillLabels(kr kref, rows [][]string) error {
	objs, err := r.getObjects(kr)
	if err != nil {
		return err
	}
	for i, o := range objs {
		if i >= len(rows) {
			break
		}
		md, _ := o["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		var kv []string
		for k, v := range labels {
			kv = append(kv, k+"="+str(v))
		}
		sort.Strings(kv)
		rows[i][len(rows[i])-1] = firstNonEmpty(strings.Join(kv, ","), "<none>")
	}
	return nil
}

// watchAfter follows changes with -w until --timeout (or Ctrl-C).
func (r *kctlRun) watchAfter(refs []kref) error {
	if !r.a.bools["watch"] && !r.a.bools["watch-only"] {
		return nil
	}
	if len(refs) != 1 {
		return kfail("you may only specify a single resource type with --watch")
	}
	kr := refs[0]
	q := r.listQuery()
	if len(kr.names) == 1 {
		q.Set("fieldSelector", "metadata.name="+kr.names[0])
	}
	body, err := r.k.Watch(r.ctx, kr.r.ObjectPath(r.space(kr.r), ""), q)
	if err != nil {
		return err
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Type   string         `json:"type"`
			Object map[string]any `json:"object"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		fmt.Fprintf(&r.stdout, "%s\t%s/%s\n", ev.Type, kindQual(kr.r), meta(ev.Object, "name"))
	}
	if r.ctx.Err() != nil {
		return nil // --timeout or Ctrl-C ends a watch normally
	}
	return sc.Err()
}

func tableCell(v any) string {
	switch x := v.(type) {
	case nil:
		return "<none>"
	case string:
		if x == "" {
			return "<none>"
		}
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// kubectlTable lays out columns three spaces apart, like kubectl.
func kubectlTable(headers []string, rows [][]string, noHeaders bool) string {
	w := make([]int, len(headers))
	all := rows
	if !noHeaders {
		all = append([][]string{headers}, rows...)
	}
	for _, row := range all {
		for i, c := range row {
			if i < len(w) && displayWidth(c) > w[i] {
				w[i] = displayWidth(c)
			}
		}
	}
	var b strings.Builder
	for _, row := range all {
		for i, c := range row {
			if i == len(row)-1 {
				b.WriteString(c)
				break
			}
			b.WriteString(c + strings.Repeat(" ", w[i]-displayWidth(c)+3))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func meta(o map[string]any, key string) string {
	md, _ := o["metadata"].(map[string]any)
	return str(md[key])
}

// readFiles reads -f FILE (or "-" is not supported: stdin is not passed).
func (r *kctlRun) readFiles() ([]kubeDoc, error) {
	files := r.a.vals["filename"]
	if len(files) == 0 {
		return nil, kfail("must specify one of -f and -k")
	}
	var docs []kubeDoc
	for _, f := range files {
		b, err := readManifest(f, r.a.bools["recursive"])
		if err != nil {
			return nil, kwrap(err)
		}
		d, err := splitYAML(b)
		if err != nil {
			return nil, kfail("%v", err)
		}
		docs = append(docs, d...)
	}
	return docs, nil
}

// sendFiles reads -f FILE for a command that sends the objects as they are
// (apply, create, replace): one that holds a value komando hid from an
// agent is refused before anything is sent (refuseHidden).
func (r *kctlRun) sendFiles() ([]kubeDoc, error) {
	docs, err := r.readFiles()
	if err != nil {
		return nil, err
	}
	if err := refuseHidden(docs); err != nil {
		return nil, kstop(toErr(err))
	}
	return docs, nil
}

// wait helper: poll until ok or the context ends.
func pollUntil(ctx context.Context, every time.Duration, fn func() (bool, error)) error {
	for {
		ok, err := fn()
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

var _ = io.Discard
