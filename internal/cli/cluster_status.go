package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

func clusterStatusCmd() *cobra.Command {
	var ns string
	var wait bool
	c := &cobra.Command{
		Use:   "status TARGET [TYPE/NAME]",
		Short: "Show the version, the nodes and what is not healthy",
		Long: `Without an object: the version, the nodes, and every problem (pods that do not
run, workloads short of replicas, nodes that are not ready; on Swarm, services
short of replicas with their tasks' errors). --namespace limits it to one
namespace. A selector that picks several clusters (@prod, kind:k8s) shows
each in data.results.

With TYPE/NAME (or TYPE NAME) on one cluster: whether that workload has
rolled out. --wait stays until it has, it fails, or --timeout (default 5m)
passes.`,
		Example: `  komando cluster status prod-k8s
  komando cluster status @prod                  # every cluster in the group, at once
  komando cluster status prod-k8s deployment/api --namespace shop --wait
  komando cluster status swarm1 service/web --wait`,
		Args: cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			ts, err := resolveClusters(st, args[0])
			if err != nil {
				return err
			}
			if len(args) > 1 {
				if len(ts) > 1 {
					return out.Usage("a rollout is on one cluster, and %q picks %d; name one of them", args[0], len(ts))
				}
				if err := noNamespace(ts[0], ns); err != nil {
					return err
				}
				typ, name, err := objectRef(args[1:])
				if err != nil {
					return err
				}
				return rolloutStatus(ownTimeLimit(cmd.Context(), wait), ts[0], typ, name, ns, wait)
			}
			if wait {
				return out.Usage("--wait needs an object: `cluster status %s deployment/NAME --wait`", args[0])
			}
			return readClusters(cmd.Context(), "cluster.status", st, ts, clusterRead{
				kube: func(ctx context.Context, t clusterTarget, k *kube.Client) (any, error) {
					return kubeStatus(ctx, k, t.conn.Name, ns)
				},
				swarm: func(ctx context.Context, t clusterTarget) (any, error) {
					if err := noNamespace(t, ns); err != nil {
						return nil, err
					}
					return swarmStatus(ctx, t)
				},
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().BoolVar(&wait, "wait", false, "with TYPE/NAME: wait until it has rolled out (--timeout, default 5m)")
	return c
}

// kubeStatus sums up a cluster, or one namespace of it.
func kubeStatus(ctx context.Context, k *kube.Client, conn, ns string) (any, error) {
	var ver map[string]any
	if err := k.Get(ctx, "/version", nil, &ver); err != nil {
		return nil, err
	}
	notes := []string{}
	// an account that may only look at its namespace may not list nodes:
	// the rest of the status is still worth showing
	nodes, _, err := listItems(ctx, k, "/api/v1/nodes")
	var ae *kube.APIError
	if errors.As(err, &ae) && ae.Code == 403 {
		notes, err = append(notes, "nodes: this account may not list them"), nil
	}
	if err != nil {
		return nil, err
	}
	space := ""
	if ns != "" {
		space = "/namespaces/" + url.PathEscape(ns)
	}
	pods, cutPods, err := listItems(ctx, k, "/api/v1"+space+"/pods")
	if err != nil {
		return nil, err
	}
	truncated := cutPods
	workloads := map[string][]map[string]any{}
	for _, kind := range []string{"deployments", "statefulsets", "daemonsets"} {
		items, cut, err := listItems(ctx, k, "/apis/apps/v1"+space+"/"+kind)
		if err != nil {
			return nil, err
		}
		workloads[kind], truncated = items, truncated || cut
	}
	ready := 0
	problems := []map[string]string{}
	problem := func(obj, reason string) {
		problems = append(problems, map[string]string{"object": obj, "problem": reason})
	}
	for _, n := range nodes {
		name := "node/" + str(n["metadata"].(map[string]any)["name"])
		if nodeReady(n) == "Ready" {
			ready++
		} else {
			problem(name, "not ready")
		}
		for _, c := range nodeConditions(n) {
			problem(name, c)
		}
	}
	bad := []string{}
	for _, p := range pods {
		m := p["metadata"].(map[string]any)
		name := str(m["namespace"]) + "/" + str(m["name"])
		st, _ := p["status"].(map[string]any)
		phase := str(st["phase"])
		down := phase != "Running" && phase != "Succeeded"
		if down {
			bad = append(bad, name)
		}
		// a crash-looping pod is still "Running": look at its containers
		if reason := podTrouble(st); reason != "" {
			problem("pod/"+name, reason)
		} else if down {
			problem("pod/"+name, strings.ToLower(phase))
		}
	}
	for _, kind := range []string{"deployment", "statefulset", "daemonset"} {
		for _, d := range workloads[kind+"s"] {
			if want, have := workloadReady(kind, d); have < want {
				m, _ := d["metadata"].(map[string]any)
				what := "replicas"
				if kind == "daemonset" {
					what = "pods"
				}
				problem(kind+"/"+str(m["namespace"])+"/"+str(m["name"]), fmt.Sprintf("%d of %d %s ready", have, want, what))
			}
		}
	}
	res := statusData{"conn": conn, "version": ver["gitVersion"], "nodes": len(nodes),
		"nodes_ready": ready, "pods_not_running": bad, "healthy": len(problems) == 0, "problems": problems}
	if truncated {
		// what was not read may hold a problem: say so instead of "healthy"
		res["truncated"] = true
		if len(problems) == 0 {
			res["healthy"] = nil
		}
		notes = append(notes, fmt.Sprintf("the cluster has more than %d objects of a kind; only those were checked (narrow it with --namespace)", maxStatusItems))
	}
	if len(notes) > 0 {
		res["notes"] = notes
	}
	if ns != "" {
		res["namespace"] = ns
	}
	return res, nil
}

// workloadReady is how many replicas (pods, for a daemonset) a workload
// wants and how many are ready.
func workloadReady(kind string, o map[string]any) (want, have int) {
	spec, _ := o["spec"].(map[string]any)
	st, _ := o["status"].(map[string]any)
	num := func(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }
	if kind == "daemonset" {
		return num(st, "desiredNumberScheduled"), num(st, "numberReady")
	}
	return num(spec, "replicas"), num(st, "readyReplicas")
}

// maxStatusItems is how many objects of one kind cluster status reads.
const maxStatusItems = 20000

// listItems reads a list page by page, up to maxStatusItems; cut is true
// when there were more.
func listItems(ctx context.Context, k *kube.Client, path string) (items []map[string]any, cut bool, err error) {
	q := url.Values{"limit": {"500"}}
	for {
		var page struct {
			Items    []map[string]any `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := k.Get(ctx, path, q, &page); err != nil {
			return nil, false, err
		}
		items = append(items, page.Items...)
		if page.Metadata.Continue == "" {
			return items, false, nil
		}
		if len(items) >= maxStatusItems {
			return items, true, nil
		}
		q.Set("continue", page.Metadata.Continue)
	}
}

// rolloutStatus reports whether one workload has rolled out, and with wait
// stays until it has (or failed, or --timeout passed).
func rolloutStatus(ctx context.Context, t clusterTarget, typ, name, ns string, wait bool) error {
	d := time.Duration(0)
	if wait {
		d = rolloutWait()
	}
	if t.host != nil {
		if swarmKind(typ) != "service" {
			return out.Usage("on Swarm, status works on services (service/NAME)")
		}
		res, err := swarmWait(ctx, t, name, d, false)
		if err != nil && res == nil {
			return err
		}
		out.P.Print("cluster.status", res, softErr(err))
		return exitFor(err)
	}
	return withKube(ctx, "cluster.status", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
		r, err := resource(ctx, k, typ)
		if err != nil {
			return nil, err
		}
		if !oneOf(r.KindName(), "Deployment", "StatefulSet", "DaemonSet") {
			return nil, out.Usage("rollout status works on deployments, statefulsets and daemonsets")
		}
		return waitRollout(ctx, k, r, cmp.Or(ns, k.Namespace), name, d)
	})
}

// podTrouble names what is wrong with a pod's containers: waiting with a
// reason (CrashLoopBackOff, ImagePullBackOff, ...) or crashed and not ready.
func podTrouble(st map[string]any) string {
	cs, _ := st["containerStatuses"].([]any)
	ics, _ := st["initContainerStatuses"].([]any)
	for _, c := range append(ics, cs...) {
		m, _ := c.(map[string]any)
		state, _ := m["state"].(map[string]any)
		if w, ok := state["waiting"].(map[string]any); ok {
			if r := str(w["reason"]); r != "" && r != "ContainerCreating" && r != "PodInitializing" {
				return str(m["name"]) + ": " + r
			}
		}
		if t, ok := state["terminated"].(map[string]any); ok && str(t["reason"]) != "Completed" && m["ready"] != true {
			return str(m["name"]) + ": " + cmp.Or(str(t["reason"]), "terminated")
		}
	}
	return ""
}

// nodeConditions lists pressure conditions that are on (MemoryPressure, ...).
func nodeConditions(n map[string]any) []string {
	st, _ := n["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	var on []string
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] != "Ready" && m["status"] == "True" {
			on = append(on, str(m["type"]))
		}
	}
	return on
}

func nodeReady(n map[string]any) string {
	st, _ := n["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] == "Ready" {
			if m["status"] == "True" {
				return "Ready"
			}
			return "NotReady"
		}
	}
	return "Unknown"
}

// summarize turns an object into one row: name, namespace, age and the few
// fields that tell its state, per kind.
func summarize(kind string, o map[string]any) map[string]any {
	m, _ := o["metadata"].(map[string]any)
	spec, _ := o["spec"].(map[string]any)
	st, _ := o["status"].(map[string]any)
	row := map[string]any{"name": m["name"], "age": age(fmt.Sprint(m["creationTimestamp"]))}
	if ns, ok := m["namespace"]; ok {
		row["namespace"] = ns
	}
	num := func(v any) int { f, _ := v.(float64); return int(f) }
	switch kind {
	case "Pod":
		row["status"] = st["phase"]
		cs, _ := st["containerStatuses"].([]any)
		ready, restarts := 0, 0
		for _, c := range cs {
			cm, _ := c.(map[string]any)
			if cm["ready"] == true {
				ready++
			}
			restarts += num(cm["restartCount"])
			if w, ok := cm["state"].(map[string]any)["waiting"].(map[string]any); ok {
				row["status"] = w["reason"]
			}
		}
		row["ready"] = fmt.Sprintf("%d/%d", ready, len(cs))
		row["restarts"] = restarts
		row["node"] = spec["nodeName"]
	case "Deployment", "StatefulSet", "ReplicaSet":
		row["ready"] = fmt.Sprintf("%d/%d", num(st["readyReplicas"]), num(spec["replicas"]))
		row["updated"] = num(st["updatedReplicas"])
		row["available"] = num(st["availableReplicas"])
	case "DaemonSet":
		row["ready"] = fmt.Sprintf("%d/%d", num(st["numberReady"]), num(st["desiredNumberScheduled"]))
	case "Service":
		row["type"], row["cluster_ip"] = spec["type"], spec["clusterIP"]
		var ports []string
		pl, _ := spec["ports"].([]any)
		for _, p := range pl {
			pm, _ := p.(map[string]any)
			ports = append(ports, fmt.Sprintf("%d/%s", num(pm["port"]), pm["protocol"]))
		}
		row["ports"] = strings.Join(ports, ",")
	case "Node":
		row["status"] = nodeReady(o)
		ni, _ := st["nodeInfo"].(map[string]any)
		row["version"] = ni["kubeletVersion"]
	case "Secret":
		row["type"] = o["type"]
		data, _ := o["data"].(map[string]any)
		row["keys"] = len(data)
	case "ConfigMap":
		data, _ := o["data"].(map[string]any)
		row["keys"] = len(data)
	case "Namespace":
		row["status"] = st["phase"]
	case "Ingress":
		var hosts []string
		rules, _ := spec["rules"].([]any)
		for _, r := range rules {
			if h, _ := r.(map[string]any)["host"].(string); h != "" {
				hosts = append(hosts, h)
			}
		}
		row["hosts"] = strings.Join(hosts, ",")
		row["class"] = spec["ingressClassName"]
		lb, _ := st["loadBalancer"].(map[string]any)
		var addrs []string
		ing, _ := lb["ingress"].([]any)
		for _, i := range ing {
			im, _ := i.(map[string]any)
			addrs = append(addrs, cmp.Or(str(im["ip"]), str(im["hostname"])))
		}
		row["address"] = strings.Join(addrs, ",")
	case "PersistentVolumeClaim":
		row["status"] = st["phase"]
		row["volume"] = spec["volumeName"]
		row["storage_class"] = spec["storageClassName"]
		if c, ok := st["capacity"].(map[string]any); ok {
			row["capacity"] = c["storage"]
		}
	case "PersistentVolume":
		row["status"] = st["phase"]
		if c, ok := spec["capacity"].(map[string]any); ok {
			row["capacity"] = c["storage"]
		}
		if ref, ok := spec["claimRef"].(map[string]any); ok {
			row["claim"] = fmt.Sprint(ref["namespace"], "/", ref["name"])
		}
		row["reclaim"] = spec["persistentVolumeReclaimPolicy"]
	case "Job":
		want := 1
		if c, ok := spec["completions"]; ok {
			want = num(c)
		}
		row["completions"] = fmt.Sprintf("%d/%d", num(st["succeeded"]), want)
		row["active"], row["failed"] = num(st["active"]), num(st["failed"])
		row["status"] = jobState(st)
	case "CronJob":
		row["schedule"], row["suspended"] = spec["schedule"], spec["suspend"] == true
		row["last_schedule"] = age(str(st["lastScheduleTime"]))
		active, _ := st["active"].([]any)
		row["active"] = len(active)
	case "HorizontalPodAutoscaler":
		row["min"], row["max"] = num(spec["minReplicas"]), num(spec["maxReplicas"])
		row["current"], row["desired"] = num(st["currentReplicas"]), num(st["desiredReplicas"])
		if ref, ok := spec["scaleTargetRef"].(map[string]any); ok {
			row["target"] = strings.ToLower(fmt.Sprint(ref["kind"])) + "/" + fmt.Sprint(ref["name"])
		}
	case "Event":
		for k, v := range eventRow(o) {
			row[k] = v
		}
	}
	return row
}

// jobState reads a Job's conditions: complete, failed or running.
func jobState(st map[string]any) string {
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["status"] == "True" && (m["type"] == "Complete" || m["type"] == "Failed") {
			return strings.ToLower(fmt.Sprint(m["type"]))
		}
	}
	return "running"
}

// eventRow is the useful part of an Event: what happened to which object,
// how often, and when last.
func eventRow(o map[string]any) map[string]any {
	inv, _ := o["involvedObject"].(map[string]any)
	last := cmp.Or(str(o["lastTimestamp"]), str(o["eventTime"]), str(o["firstTimestamp"]))
	if m, ok := o["metadata"].(map[string]any); ok && last == "" {
		last = str(m["creationTimestamp"])
	}
	count, _ := o["count"].(float64)
	return map[string]any{
		"type": o["type"], "reason": o["reason"], "message": o["message"], "count": int(count),
		"object": strings.ToLower(str(inv["kind"])) + "/" + str(inv["name"]), "last": last, "last_age": age(last),
	}
}
