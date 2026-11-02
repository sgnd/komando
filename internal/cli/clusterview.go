package cli

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
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
		Short: "Recent events, oldest first (--warnings for problems only, --for TYPE/NAME for one object)",
		Example: `  komando cluster events prod-k8s --namespace shop --warnings
  komando cluster events prod-k8s --for deployment/api --namespace shop`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				return out.Usage("events are a Kubernetes view; on Swarm, `cluster ls TARGET tasks` shows failed tasks and their errors")
			}
			return withKube(cmd.Context(), "cluster.events", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				kind, name := "", ""
				if of != "" {
					typ, n, err := splitRef(of)
					if err != nil {
						return nil, err
					}
					r, err := k.Resource(ctx, typ)
					if err != nil {
						return nil, out.Usage("%v", err)
					}
					kind, name = r.KindName(), n
				}
				space := firstNonEmpty(ns, k.Namespace)
				if all {
					space = ""
				}
				rows, err := clusterEvents(ctx, k, space, kind, name, warnings, limit)
				if err != nil {
					return nil, err
				}
				return map[string]any{"conn": t.conn.Name, "namespace": space, "count": len(rows), "events": rows}, nil
			})
		},
	}
	nsFlags(c, &ns, &all)
	c.Flags().BoolVar(&warnings, "warnings", false, "only Warning events")
	c.Flags().StringVar(&of, "for", "", "only events about this object, e.g. deployment/api")
	c.Flags().IntVarP(&limit, "limit", "n", 100, "max events (the newest)")
	return c
}

func clusterDescribeCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "describe TARGET TYPE NAME",
		Short: "One object in short: state, conditions, containers or pods, and its recent events",
		Example: `  komando cluster describe prod-k8s pod api-7d9f-x2 --namespace shop
  komando cluster describe prod-k8s deployment api --namespace shop
  komando cluster describe swarm-manager service web`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				if !strings.HasPrefix(args[1], "service") {
					return out.Usage("on Swarm, describe works for services (its tasks and their errors)")
				}
				return swarmRead(cmd.Context(), "cluster.describe", t, "docker service ps "+sshx.Q(args[2])+" --no-trunc --format '{{json .}}'")
			}
			return withKube(cmd.Context(), "cluster.describe", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, args[1])
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				space := ""
				if r.IsNamespaced() {
					space = firstNonEmpty(ns, k.Namespace)
				}
				var o map[string]any
				if err := k.Get(ctx, r.ObjectPath(space, args[2]), nil, &o); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "object": strings.ToLower(r.KindName()) + "/" + args[2], "summary": summarize(r.KindName(), o)}
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
				if events, err := clusterEvents(ctx, k, space, r.KindName(), args[2], false, 20); err == nil {
					res["events"] = events
				}
				return res, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
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
