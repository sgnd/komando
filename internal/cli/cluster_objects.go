package cli

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

func clusterLsCmd() *cobra.Command {
	var ns, selector string
	var all bool
	var limit int
	c := &cobra.Command{
		Use:   "ls TARGET TYPE",
		Short: "List pods, deployments, services, nodes ... (Swarm: services, tasks)",
		Example: `  komando cluster ls prod-k8s pods --namespace shop
  komando cluster ls prod-k8s deploy -A
  komando cluster ls @prod nodes                # every cluster in the group
  komando cluster ls swarm-manager services
  komando cluster ls swarm-manager tasks -n 20`,
		Args: cobra.ExactArgs(2),
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
			swarm := func(ctx context.Context, t clusterTarget) (any, error) {
				if err := noNamespace(t, ns); err != nil {
					return nil, err
				}
				kind := swarmKind(args[1])
				if kind == "" {
					return nil, out.Usage("Swarm lists services (svc), tasks, nodes or stacks; %q is none of them", args[1])
				}
				return swarmList(ctx, t, kind, selector, limit)
			}
			return readClusters(cmd.Context(), "cluster.ls", st, ts, clusterRead{swarm: swarm, kube: func(ctx context.Context, t clusterTarget, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, args[1])
				if err != nil {
					return nil, err
				}
				space := cmp.Or(ns, k.Namespace)
				if all {
					space = ""
				}
				q := url.Values{}
				if limit > 0 {
					q.Set("limit", strconv.Itoa(limit))
				}
				if selector != "" {
					q.Set("labelSelector", selector)
				}
				var list struct {
					Items    []map[string]any `json:"items"`
					Metadata struct {
						Continue string `json:"continue"`
					} `json:"metadata"`
				}
				if err := k.Get(ctx, r.ObjectPath(space, ""), q, &list); err != nil {
					return nil, err
				}
				rows := []map[string]any{}
				for _, o := range list.Items {
					rows = append(rows, summarize(r.KindName(), o))
				}
				res := kubeList{"conn": t.conn.Name, "type": r.KindName(), "count": len(rows), "items": rows}
				if r.IsNamespaced() && !all {
					res["namespace"] = space
				}
				if list.Metadata.Continue != "" {
					res["truncated"] = true
				}
				return res, nil
			}})
		},
	}
	nsFlags(c, &ns, &all, &limitOpt{&limit, 500, "the most objects to show"})
	c.Flags().StringVarP(&selector, "selector", "l", "", "only objects with these labels, e.g. app=api or 'tier in (web,api)'")
	return c
}

func clusterGetCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "get TARGET TYPE NAME",
		Short: "Show one object in full (Secret values are hidden); TYPE/NAME works too",
		Example: `  komando cluster get prod-k8s deployment api --namespace shop
  komando cluster get prod-k8s deployment.apps/api --namespace shop
  komando cluster get swarm-manager service/web`,
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
				res, err := swarmGet(cmd.Context(), t, typ, name)
				if err != nil {
					return err
				}
				out.P.Print("cluster.get", res, nil)
				return nil
			}
			return withKube(cmd.Context(), "cluster.get", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				var o map[string]any
				if err := k.Get(ctx, r.ObjectPath(cmp.Or(ns, k.Namespace), name), nil, &o); err != nil {
					return nil, err
				}
				redact(o)
				maskObject(o)
				if m, ok := o["metadata"].(map[string]any); ok {
					delete(m, "managedFields")
				}
				return o, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}

// logText is the logs of one pod, or of the pods of a workload (object)
// or a label selector.
type logText struct {
	Object    string   `json:"object,omitempty"` // deployment/api, or the -l selector
	Pod       string   `json:"pod,omitempty"`    // when one pod was read
	Namespace string   `json:"namespace"`
	Logs      string   `json:"logs"`
	Pods      []string `json:"pods"`
}

func (l logText) Text() string { return l.Logs }

func clusterRestartCmd() *cobra.Command {
	var ns string
	var wait bool
	c := &cobra.Command{
		Use:   "restart TARGET TYPE/NAME",
		Short: "Restart a deployment, statefulset or daemonset (rolling), or a Swarm service",
		Example: `  komando cluster restart prod-k8s deployment/api --namespace shop --wait
  komando cluster restart swarm-manager service/web`,
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
					return out.Usage("on Swarm, restart works on services (service/NAME)")
				}
				if _, err := swarmInspect(cmd.Context(), t, name); err != nil {
					return err
				}
				return swarmChange(cmd.Context(), "cluster.restart", t, name, "docker service update --force --detach "+sshx.Q(name), wait, false, driver.RiskWrite,
					map[string]any{"restarted": "service/" + name})
			}
			return withKube(ownTimeLimit(cmd.Context(), wait), "cluster.restart", t, driver.RiskWrite, map[string]any{"object": typ + "/" + name}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "DaemonSet") {
					return nil, out.Usage("restart works on deployments, statefulsets and daemonsets")
				}
				patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339))
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				space := cmp.Or(ns, k.Namespace)
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name), q, []byte(patch), "application/strategic-merge-patch+json"); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "restarted": kindRef(r, name), "namespace": space, "dry_run": g.dryRun}
				return withRollout(ctx, k, r, space, name, wait, res)
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().BoolVar(&wait, "wait", false, "wait until the restart has rolled out (--timeout, default 5m)")
	return c
}

// kindRef is "deployment/api".
func kindRef(r kube.ResourceType, name string) string {
	return strings.ToLower(r.KindName()) + "/" + name
}

// withRollout adds the rollout to res when wait is set (and it is no dry run).
func withRollout(ctx context.Context, k *kube.Client, r kube.ResourceType, space, name string, wait bool, res map[string]any) (any, error) {
	if !wait || g.dryRun {
		return res, nil
	}
	ro, err := waitRollout(ctx, k, r, space, name, rolloutWait())
	res["rollout"] = ro
	if err != nil {
		return res, err
	}
	return res, nil
}

func oneOf(v string, in ...string) bool {
	for _, x := range in {
		if v == x {
			return true
		}
	}
	return false
}

func clusterScaleCmd() *cobra.Command {
	var ns string
	var wait bool
	c := &cobra.Command{
		Use:   "scale TARGET TYPE/NAME REPLICAS",
		Short: "Set the number of replicas (0 stops it: needs --allow-dangerous)",
		Example: `  komando cluster scale prod-k8s deployment/api 3 --namespace shop --wait
  komando cluster scale swarm-manager service/web 4`,
		Args: refArgs(1, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[len(args)-1])
			if err != nil || n < 0 {
				return out.Usage("REPLICAS must be a number, 0 or more")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := objectRef(args[1 : len(args)-1])
			if err != nil {
				return err
			}
			risk := driver.RiskWrite
			if n == 0 {
				risk = driver.RiskDestructive // stopping every replica is an outage
			}
			if t.host != nil {
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				return swarmScale(cmd.Context(), t, typ, name, n, wait, risk)
			}
			return withKube(ownTimeLimit(cmd.Context(), wait), "cluster.scale", t, risk, map[string]any{"object": typ + "/" + name, "replicas": n}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "ReplicaSet", "ReplicationController") {
					return nil, out.Usage("scale works on deployments, statefulsets and replicasets, not %s", strings.ToLower(r.KindName())+"s")
				}
				space := cmp.Or(ns, k.Namespace)
				var cur struct {
					Spec struct {
						Replicas int `json:"replicas"`
					} `json:"spec"`
				}
				if err := k.Get(ctx, r.ObjectPath(space, name)+"/scale", nil, &cur); err != nil {
					return nil, err
				}
				res := map[string]any{"conn": t.conn.Name, "scaled": kindRef(r, name), "replicas": n, "previous_replicas": cur.Spec.Replicas,
					"namespace": space, "dry_run": g.dryRun}
				if cur.Spec.Replicas == n {
					res["unchanged"] = true
					return withRollout(ctx, k, r, space, name, wait, res)
				}
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				body := fmt.Sprintf(`{"spec":{"replicas":%d}}`, n)
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name)+"/scale", q, []byte(body), "application/merge-patch+json"); err != nil {
					return nil, err
				}
				return withRollout(ctx, k, r, space, name, wait, res)
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().BoolVar(&wait, "wait", false, "wait until every replica is ready (--timeout, default 5m)")
	return c
}

// swarmScale sets a replicated service's replica count.
func swarmScale(ctx context.Context, t clusterTarget, typ, name string, n int, wait bool, risk driver.Risk) error {
	if swarmKind(typ) != "service" {
		return out.Usage("on Swarm, scale works on services (service/NAME)")
	}
	ins, err := swarmInspect(ctx, t, name)
	if err != nil {
		return err
	}
	prev := serviceReplicas(ins["Spec"])
	if prev < 0 {
		return out.Usage("service %s is global (one task per node); scale works on replicated services", name)
	}
	res := map[string]any{"host": t.host.Name, "scaled": "service/" + name, "replicas": n, "previous_replicas": prev}
	if prev == n {
		res["unchanged"] = true
		out.P.Print("cluster.scale", res, nil)
		return nil
	}
	line := "docker service scale --detach " + sshx.Q(name+"="+strconv.Itoa(n))
	return swarmChange(ctx, "cluster.scale", t, name, line, wait, false, risk, res)
}
