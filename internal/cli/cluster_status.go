package cli

import (
	"context"
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
		Short: "Version, nodes and what is not healthy; or one rollout",
		Long: `Without an object: the version, the nodes, and every problem (pods that do not
run, workloads short of replicas, nodes that are not ready; on Swarm, services
short of replicas with their tasks' errors). --namespace limits it to one
namespace. A selector that picks several clusters (@prod, kind:k8s) shows
each in data.results. With TYPE/NAME (or TYPE NAME) on one cluster: whether
that workload has rolled out;
--wait stays until it has, it fails, or --timeout (default 5m) passes.`,
		Example: `  komando cluster status prod-k8s
  komando cluster status @prod                  # every cluster in the group, at once
  komando cluster status prod-k8s deployment/api --namespace shop --wait
  komando cluster status swarm-manager service/web --wait`,
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
				return rolloutStatus(cmd.Context(), ts[0], typ, name, ns, wait)
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
	var nodes, pods, deploys struct {
		Items []map[string]any `json:"items"`
	}
	if err := k.Get(ctx, "/api/v1/nodes", nil, &nodes); err != nil {
		return nil, err
	}
	podPath, deployPath := "/api/v1/pods", "/apis/apps/v1/deployments"
	if ns != "" {
		podPath = "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods"
		deployPath = "/apis/apps/v1/namespaces/" + url.PathEscape(ns) + "/deployments"
	}
	if err := k.Get(ctx, podPath, url.Values{"limit": {"5000"}}, &pods); err != nil {
		return nil, err
	}
	if err := k.Get(ctx, deployPath, url.Values{"limit": {"2000"}}, &deploys); err != nil {
		return nil, err
	}
	ready := 0
	problems := []map[string]string{}
	problem := func(obj, reason string) {
		problems = append(problems, map[string]string{"object": obj, "problem": reason})
	}
	for _, n := range nodes.Items {
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
	for _, p := range pods.Items {
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
	for _, d := range deploys.Items {
		m, _ := d["metadata"].(map[string]any)
		spec, _ := d["spec"].(map[string]any)
		st, _ := d["status"].(map[string]any)
		want, _ := spec["replicas"].(float64)
		have, _ := st["readyReplicas"].(float64)
		if have < want {
			problem("deployment/"+str(m["namespace"])+"/"+str(m["name"]), fmt.Sprintf("%d of %d replicas ready", int(have), int(want)))
		}
	}
	res := statusData{"conn": conn, "version": ver["gitVersion"], "nodes": len(nodes.Items),
		"nodes_ready": ready, "pods_not_running": bad, "healthy": len(problems) == 0, "problems": problems}
	if ns != "" {
		res["namespace"] = ns
	}
	return res, nil
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
		return waitRollout(ctx, k, r, firstNonEmpty(ns, k.Namespace), name, d)
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
			return str(m["name"]) + ": " + firstNonEmpty(str(t["reason"]), "terminated")
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
			addrs = append(addrs, firstNonEmpty(str(im["ip"]), str(im["hostname"])))
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
	last := firstNonEmpty(str(o["lastTimestamp"]), str(o["eventTime"]), str(o["firstTimestamp"]))
	if m, ok := o["metadata"].(map[string]any); ok && last == "" {
		last = str(m["creationTimestamp"])
	}
	count, _ := o["count"].(float64)
	return map[string]any{
		"type": o["type"], "reason": o["reason"], "message": o["message"], "count": int(count),
		"object": strings.ToLower(str(inv["kind"])) + "/" + str(inv["name"]), "last": last, "last_age": age(last),
	}
}
