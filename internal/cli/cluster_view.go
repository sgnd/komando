package cli

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
)

// clusterEvents reads events, oldest first, optionally for one object or
// only warnings.
func clusterEvents(ctx context.Context, k *kube.Client, space, kind, name string, warnings bool, limit int) ([]map[string]any, error) {
	var fs []string
	if warnings {
		fs = append(fs, "type=Warning")
	}
	if name != "" {
		fs = append(fs, "involvedObject.name="+name)
	}
	if kind != "" {
		fs = append(fs, "involvedObject.kind="+kind)
	}
	q := url.Values{}
	if len(fs) > 0 {
		q.Set("fieldSelector", strings.Join(fs, ","))
	}
	path := "/api/v1/events"
	if space != "" {
		path = "/api/v1/namespaces/" + url.PathEscape(space) + "/events"
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := k.Get(ctx, path, q, &list); err != nil {
		return nil, err
	}
	rows := make([]map[string]any, 0, len(list.Items))
	for _, e := range list.Items {
		r := eventRow(e)
		if space == "" {
			if m, ok := e["metadata"].(map[string]any); ok {
				r["namespace"] = str(m["namespace"])
			}
		}
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool { return str(rows[i]["last"]) < str(rows[j]["last"]) })
	if limit > 0 && len(rows) > limit {
		out.P.Cut(limit)
		rows = rows[len(rows)-limit:]
	}
	return rows, nil
}

func clusterEventsCmd() *cobra.Command {
	var ns, of string
	var all, warnings bool
	var limit int
	c := &cobra.Command{
		Use:   "events TARGET",
		Short: "Recent events, oldest first (--warnings for problems only)",
		Example: `  komando cluster events prod-k8s --namespace shop --warnings
  komando cluster events @prod --warnings -A    # problems in every cluster of the group
  komando cluster events prod-k8s --for deployment/api --namespace shop`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := nsOrAll(ns, all); err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			ts, err := resolveClusters(st, args[0])
			if err != nil {
				return err
			}
			return readClusters(cmd.Context(), "cluster.events", st, ts, clusterRead{
				swarmNo: "events are a Kubernetes view; on Swarm, `cluster list TARGET tasks` shows failed tasks and their errors",
				kube: func(ctx context.Context, t clusterTarget, k *kube.Client) (any, error) {
					kind, name := "", ""
					if of != "" {
						typ, n, err := splitRef(of)
						if err != nil {
							return nil, err
						}
						r, err := resource(ctx, k, typ)
						if err != nil {
							return nil, err
						}
						kind, name = r.KindName(), n
					}
					space := cmp.Or(ns, k.Namespace)
					if all {
						space = ""
					}
					rows, err := clusterEvents(ctx, k, space, kind, name, warnings, limit)
					if err != nil {
						return nil, err
					}
					return eventList{"conn": t.conn.Name, "namespace": space, "count": len(rows), "events": rows}, nil
				}})
		},
	}
	nsFlags(c, &ns, &all, &limitOpt{&limit, 100, "the most events to show (the newest)"})
	c.Flags().BoolVar(&warnings, "warnings", false, "only Warning events")
	c.Flags().StringVar(&of, "for", "", "only events about this object, like deployment/api")
	return c
}

func clusterDescribeCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "describe TARGET TYPE/NAME",
		Short: "One object in short: state, images, conditions, pods, events",
		Example: `  komando cluster describe prod-k8s pod/api-7d9f-x2 --namespace shop
  komando cluster describe prod-k8s deployment/api --namespace shop
  komando cluster describe swarm1 service/web`,
		Args: refArgs(1, 0),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := objectRef(args[1:])
			if err != nil {
				return err
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if swarmKind(typ) != "service" {
					return out.Usage("on Swarm, describe works for services (its tasks and their errors)")
				}
				res, err := swarmDescribe(cmd.Context(), t, name)
				if err != nil {
					return err
				}
				out.P.Print("cluster.describe", res, nil)
				return nil
			}
			return withKube(cmd.Context(), "cluster.describe", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				space := ""
				if r.IsNamespaced() {
					space = cmp.Or(ns, k.Namespace)
				}
				return describeObject(ctx, k, t.conn.Name, r, name, space)
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}

// describeObject is one object in short: its summary, conditions, pods or
// containers, endpoints and recent events.
func describeObject(ctx context.Context, k *kube.Client, conn string, r kube.ResourceType, name, space string) (describeData, error) {
	var o map[string]any
	if err := k.Get(ctx, r.ObjectPath(space, name), nil, &o); err != nil {
		return nil, err
	}
	o["kind"] = r.KindName()
	sum := summarize(r.KindName(), o)
	for k, v := range describeMore(r.KindName(), o) {
		sum[k] = v
	}
	res := describeData{"conn": conn, "object": kindRef(r, name), "summary": sum}
	stat, _ := o["status"].(map[string]any)
	if conds := conditions(stat); len(conds) > 0 {
		res["conditions"] = conds
	}
	if r.KindName() == "Pod" {
		res["containers"] = containerStates(o)
	} else if sel := matchLabels(o); sel != "" && space != "" {
		var pods struct {
			Items []map[string]any `json:"items"`
		}
		if err := k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods", url.Values{"labelSelector": {sel}}, &pods); err == nil {
			rows := []map[string]any{}
			for _, p := range pods.Items {
				rows = append(rows, summarize("Pod", p))
			}
			res["pods"] = rows
		}
	}
	if r.KindName() == "Service" && space != "" {
		res["endpoints"] = endpoints(ctx, k, space, name)
	}
	if events, err := clusterEvents(ctx, k, space, r.KindName(), name, false, 20); err == nil {
		res["events"] = events
	}
	return res, nil
}

// describeMore adds what `describe` shows beyond the `ls` row: images,
// strategy and selector of a workload; selector and target ports of a
// Service.
func describeMore(kind string, o map[string]any) map[string]any {
	spec, _ := o["spec"].(map[string]any)
	more := map[string]any{}
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		tpl, _ := spec["template"].(map[string]any)
		ps, _ := tpl["spec"].(map[string]any)
		cs, _ := ps["containers"].([]any)
		var imgs []string
		for _, c := range cs {
			m, _ := c.(map[string]any)
			imgs = append(imgs, str(m["name"])+"="+str(m["image"]))
		}
		more["images"] = strings.Join(imgs, ", ")
		if sel := matchLabels(o); sel != "" {
			more["selector"] = sel
		}
		for _, f := range []string{"strategy", "updateStrategy"} {
			if st, ok := spec[f].(map[string]any); ok {
				s := str(st["type"])
				if ru, ok := st["rollingUpdate"].(map[string]any); ok {
					s += fmt.Sprintf(" (max surge %v, max unavailable %v)", firstAny(ru["maxSurge"], "-"), firstAny(ru["maxUnavailable"], "-"))
				}
				more["strategy"] = s
			}
		}
		if a, ok := o["metadata"].(map[string]any)["annotations"].(map[string]any); ok && a[revisionKey] != nil {
			more["revision"] = a[revisionKey]
		}
	case "Service":
		if sel := matchLabels(o); sel != "" {
			more["selector"] = sel
		}
		pl, _ := spec["ports"].([]any)
		var ports []string
		for _, p := range pl {
			m, _ := p.(map[string]any)
			s := fmt.Sprintf("%v->%v/%v", cluCell(m["port"]), cluCell(firstAny(m["targetPort"], m["port"])), firstAny(m["protocol"], "TCP"))
			if n := str(m["name"]); n != "" {
				s = n + " " + s
			}
			if np := m["nodePort"]; np != nil {
				s += fmt.Sprintf(" (node port %v)", cluCell(np))
			}
			ports = append(ports, s)
		}
		more["target_ports"] = strings.Join(ports, ", ")
	}
	return more
}

func firstAny(v ...any) any {
	for _, x := range v {
		if x != nil {
			return x
		}
	}
	return nil
}

// endpoints are the pod addresses behind a Service, ready or not.
func endpoints(ctx context.Context, k *kube.Client, space, name string) []map[string]any {
	var ep map[string]any
	rows := []map[string]any{}
	if k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/endpoints/"+url.PathEscape(name), nil, &ep) != nil {
		return rows
	}
	subsets, _ := ep["subsets"].([]any)
	for _, s := range subsets {
		sm, _ := s.(map[string]any)
		for key, ready := range map[string]bool{"addresses": true, "notReadyAddresses": false} {
			as, _ := sm[key].([]any)
			for _, a := range as {
				am, _ := a.(map[string]any)
				ref, _ := am["targetRef"].(map[string]any)
				rows = append(rows, map[string]any{"ip": str(am["ip"]), "pod": str(ref["name"]), "ready": ready})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return str(rows[i]["pod"]) < str(rows[j]["pod"]) })
	return rows
}

// matchLabels turns a workload's spec.selector.matchLabels into a label
// selector ("app=api,tier=web"), or "" when it has none.
func matchLabels(o map[string]any) string {
	spec, _ := o["spec"].(map[string]any)
	sel, _ := spec["selector"].(map[string]any)
	ml, _ := sel["matchLabels"].(map[string]any)
	if ml == nil {
		if svcSel, ok := spec["selector"].(map[string]any); ok && o["kind"] == "Service" {
			ml = svcSel // a Service selects pods with plain labels
		}
	}
	var parts []string
	for k, v := range ml {
		parts = append(parts, k+"="+str(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// conditions lists status.conditions as type, status, reason and message.
func conditions(st map[string]any) []map[string]any {
	cs, _ := st["conditions"].([]any)
	rows := []map[string]any{}
	for _, c := range cs {
		m, _ := c.(map[string]any)
		rows = append(rows, map[string]any{"type": m["type"], "status": m["status"], "reason": m["reason"], "message": m["message"]})
	}
	return rows
}

// containerStates is a pod's containers: image, ready, restarts and state
// with its reason (waiting: CrashLoopBackOff, terminated: OOMKilled, ...).
func containerStates(pod map[string]any) []map[string]any {
	st, _ := pod["status"].(map[string]any)
	cs, _ := st["containerStatuses"].([]any)
	rows := []map[string]any{}
	for _, c := range cs {
		m, _ := c.(map[string]any)
		row := map[string]any{"name": m["name"], "image": m["image"], "ready": m["ready"] == true}
		if n, ok := m["restartCount"].(float64); ok {
			row["restarts"] = int(n)
		}
		state, _ := m["state"].(map[string]any)
		for k, v := range state {
			row["state"] = k
			if d, ok := v.(map[string]any); ok {
				row["reason"], row["message"] = d["reason"], d["message"]
				if code, ok := d["exitCode"].(float64); ok {
					row["exit_code"] = int(code)
				}
			}
		}
		if ls, ok := m["lastState"].(map[string]any); ok {
			if last, ok := ls["terminated"].(map[string]any); ok {
				row["last_exit"] = map[string]any{"reason": last["reason"], "exit_code": last["exitCode"], "finished": last["finishedAt"]}
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// eventList is `cluster events`: a table for a person.
type eventList map[string]any

func (e eventList) Text() string {
	rows, _ := e["events"].([]map[string]any)
	if len(rows) == 0 {
		if ns := str(e["namespace"]); ns != "" {
			return noneYet("events in namespace "+ns, "", "-A looks in every namespace")
		}
		return noneYet("events", "")
	}
	cols := listColumns["Event"]
	if str(e["namespace"]) == "" {
		cols = append([][2]string{{"namespace", "namespace"}}, cols...)
	}
	return tableOf(cols, rows)
}
