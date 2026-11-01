package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// `komando cluster` works the same on Kubernetes (a k8s conn: the API is
// called directly, through --via and VPNs) and Docker Swarm (a manager
// server: docker runs there over SSH). Verbs that exist in both engines
// sit directly under `cluster` (docs/design/vision.md).

type clusterTarget struct {
	conn *store.Conn // Kubernetes
	host *store.Host // Swarm manager
}

func resolveCluster(st *store.State, expr string) (clusterTarget, error) {
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return clusterTarget{}, err
	}
	var k8s []*store.Conn
	for _, c := range sel.Conns {
		if connFamily(c) == "cluster" {
			k8s = append(k8s, c)
		}
	}
	switch {
	case len(k8s) == 1 && len(sel.Hosts) == 0:
		return clusterTarget{conn: k8s[0]}, nil
	case len(k8s) == 0 && len(sel.Hosts) == 1:
		return clusterTarget{host: sel.Hosts[0]}, nil
	case len(k8s)+len(sel.Hosts) == 0:
		return clusterTarget{}, noMatch(expr, "clusters (a k8s conn, or a Swarm manager server)", sel)
	}
	return clusterTarget{}, out.Usage("target %q picks %d clusters; this command works on one", expr, len(k8s)+len(sel.Hosts))
}

// kubeClient opens the API of a k8s conn through its --via path.
func kubeClient(ctx context.Context, st *store.State, c *store.Conn) (*kube.Client, func(), error) {
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := kube.Parse([]byte(a.Password))
	if err != nil {
		a.Close()
		return nil, nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		a.Close()
		return nil, nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	if ns := c.Options["namespace"]; ns != "" {
		x.Namespace = ns
	}
	var dial kube.Dialer
	if a.Dial != nil {
		dial = kube.Dialer(a.Dial)
	}
	k, err := kube.New(x, dial)
	if err != nil {
		a.Close()
		return nil, nil, out.Errf(out.ExitUsage, "KUBECONFIG", "check the kubeconfig", "conn %s: %v", c.Name, err)
	}
	return k, a.Close, nil
}

func kubeErr(err error) error {
	if e, ok := err.(*kube.APIError); ok {
		code, exit := "K8S_ERROR", out.ExitRemote
		switch e.Code {
		case 401, 403:
			code, exit = "K8S_FORBIDDEN", out.ExitConnect
		case 404:
			code, exit = "K8S_NOT_FOUND", out.ExitNotFound
		case 409:
			code, exit = "K8S_CONFLICT", out.ExitConflict
		}
		return out.Errf(exit, code, "", "%s", e.Error())
	}
	if _, ok := err.(*out.Error); ok {
		return err
	}
	return out.Errf(out.ExitConnect, "K8S_UNREACHABLE", "check the conn with `komando test NAME` (and its --via path)", "%v", err)
}

// withKube runs fn on a k8s conn after the safety check for risk.
func withKube(ctx context.Context, name string, t clusterTarget, risk driver.Risk, extra map[string]any,
	fn func(ctx context.Context, k *kube.Client) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster"}, Reasons: []string{name}}); err != nil {
		if g.dryRun {
			out.P.Print(name, map[string]any{"conn": t.conn.Name, "dry_run": true, "would_be_blocked": toErr(err)}, nil)
			return nil
		}
		return err
	}
	k, done, err := kubeClient(ctx, st, t.conn)
	if err != nil {
		return err
	}
	defer done()
	res, err := fn(ctx, k)
	rec := map[string]any{"conns": []string{t.conn.Name}, "risk": risk.String()}
	for key, v := range extra {
		rec[key] = v
	}
	if err != nil {
		err = kubeErr(err)
		rec["error"] = toErr(err).Code
	}
	if risk > driver.RiskRead {
		audit(st, name, nil, "", err == nil, rec)
	}
	if err != nil {
		return err
	}
	out.P.Print(name, res, nil)
	return nil
}

// swarm runs a docker command on the manager. Reads are parsed as JSON
// lines; changes go through the usual guard (protected servers need --yes).
func swarmRead(ctx context.Context, name string, t clusterTarget, command string) error {
	return probe(ctx, name, t.host.Name, command, false, func(_ *store.Host, s string) (any, error) {
		rows := []map[string]any{}
		sc := bufio.NewScanner(strings.NewReader(s))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				return nil, fmt.Errorf("unexpected docker output: %s", line)
			}
			rows = append(rows, m)
		}
		return rows, nil
	})
}

func age(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// --- commands ---------------------------------------------------------------

func clusterCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "cluster",
		Aliases: []string{"k8s", "kube", "swarm"},
		Short:   "Kubernetes and Docker Swarm: status, list, logs, restart, scale, apply",
		Long: `TARGET is a k8s conn (add one with ` + "`komando import kubeconfig`" + `) or a Swarm
manager server. The same verbs work on both. Reads need nothing; restart,
scale and apply change the cluster (protected targets need --yes; try
--dry-run); rm needs --allow-dangerous. Anything else: ` + "`cluster run`" + `
passes the native kubectl or docker command, read-only unless --write.`,
	}
	c.AddCommand(clusterStatusCmd(), clusterLsCmd(), clusterGetCmd(), clusterLogsCmd(), clusterRestartCmd(),
		clusterScaleCmd(), clusterApplyCmd(), clusterRmCmd(), clusterRunCmd())
	return c
}

func clusterStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status TARGET",
		Short:   "Version, nodes, and what is not healthy",
		Example: "  komando cluster status prod-k8s\n  komando cluster status swarm-manager",
		Args:    cobra.ExactArgs(1),
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
				return swarmRead(cmd.Context(), "cluster.status", t,
					`docker info --format '{{json .Swarm}}' && docker node ls --format '{{json .}}' && docker service ls --format '{{json .}}'`)
			}
			return withKube(cmd.Context(), "cluster.status", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				var ver map[string]any
				if err := k.Get(ctx, "/version", nil, &ver); err != nil {
					return nil, err
				}
				var nodes, pods struct {
					Items []map[string]any `json:"items"`
				}
				if err := k.Get(ctx, "/api/v1/nodes", nil, &nodes); err != nil {
					return nil, err
				}
				if err := k.Get(ctx, "/api/v1/pods", url.Values{"fieldSelector": {"status.phase!=Running,status.phase!=Succeeded"}}, &pods); err != nil {
					return nil, err
				}
				ready := 0
				for _, n := range nodes.Items {
					if nodeReady(n) == "Ready" {
						ready++
					}
				}
				var bad []string
				for _, p := range pods.Items {
					m := p["metadata"].(map[string]any)
					bad = append(bad, fmt.Sprint(m["namespace"], "/", m["name"]))
				}
				return map[string]any{"conn": t.conn.Name, "version": ver["gitVersion"], "nodes": len(nodes.Items),
					"nodes_ready": ready, "pods_not_running": bad}, nil
			})
		},
	}
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
	case "DaemonSet":
		row["ready"] = fmt.Sprintf("%d/%d", num(st["numberReady"]), num(st["desiredNumberScheduled"]))
	case "Service":
		row["type"], row["cluster_ip"] = spec["type"], spec["clusterIP"]
		var ports []string
		for _, p := range spec["ports"].([]any) {
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
	}
	return row
}

// redact keeps the keys of a Secret and drops their values: secret values
// never reach komando's output.
func redact(o map[string]any) {
	if o["kind"] != "Secret" {
		return
	}
	for _, f := range []string{"data", "stringData"} {
		if d, ok := o[f].(map[string]any); ok {
			for k := range d {
				d[k] = "(hidden)"
			}
		}
	}
	if m, ok := o["metadata"].(map[string]any); ok {
		if a, ok := m["annotations"].(map[string]any); ok {
			delete(a, "kubectl.kubernetes.io/last-applied-configuration")
		}
	}
}

func nsFlags(c *cobra.Command, ns *string, all *bool) {
	c.Flags().StringVar(ns, "namespace", "", "Kubernetes namespace (default: the context's, else default)")
	if all != nil {
		c.Flags().BoolVar(all, "all-namespaces", false, "every namespace")
	}
}

func clusterLsCmd() *cobra.Command {
	var ns string
	var all bool
	var limit int
	c := &cobra.Command{
		Use:   "ls TARGET TYPE",
		Short: "List pods, deployments, services, nodes, ... (Swarm: services, nodes, tasks, stacks)",
		Example: `  komando cluster ls prod-k8s pods --namespace shop
  komando cluster ls prod-k8s deploy --all-namespaces
  komando cluster ls swarm-manager services`,
		Args: cobra.ExactArgs(2),
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
				q := map[string]string{
					"services": "docker service ls --format '{{json .}}'", "service": "docker service ls --format '{{json .}}'",
					"nodes": "docker node ls --format '{{json .}}'", "node": "docker node ls --format '{{json .}}'",
					"stacks": "docker stack ls --format '{{json .}}'", "stack": "docker stack ls --format '{{json .}}'",
					"tasks": "for s in $(docker service ls -q); do docker service ps $s --format '{{json .}}'; done",
				}[strings.ToLower(args[1])]
				if q == "" {
					return out.Usage("Swarm lists services, nodes, tasks or stacks")
				}
				return swarmRead(cmd.Context(), "cluster.ls", t, q)
			}
			return withKube(cmd.Context(), "cluster.ls", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, args[1])
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				space := firstNonEmpty(ns, k.Namespace)
				if all {
					space = ""
				}
				q := url.Values{}
				if limit > 0 {
					q.Set("limit", strconv.Itoa(limit))
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
				res := map[string]any{"conn": t.conn.Name, "type": r.KindName(), "count": len(rows), "items": rows}
				if r.IsNamespaced() && !all {
					res["namespace"] = space
				}
				if list.Metadata.Continue != "" {
					res["truncated"] = true
				}
				return res, nil
			})
		},
	}
	nsFlags(c, &ns, &all)
	c.Flags().IntVarP(&limit, "limit", "n", 500, "max items")
	return c
}

func clusterGetCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "get TARGET TYPE NAME",
		Short: "Show one object in full (Secret values are hidden)",
		Args:  cobra.ExactArgs(3),
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
				return swarmRead(cmd.Context(), "cluster.get", t, "docker "+sshx.Q(args[1])+" inspect "+sshx.Q(args[2])+" --format '{{json .}}'")
			}
			return withKube(cmd.Context(), "cluster.get", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, args[1])
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				var o map[string]any
				if err := k.Get(ctx, r.ObjectPath(firstNonEmpty(ns, k.Namespace), args[2]), nil, &o); err != nil {
					return nil, err
				}
				redact(o)
				if m, ok := o["metadata"].(map[string]any); ok {
					delete(m, "managedFields")
				}
				return o, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
}

func clusterLogsCmd() *cobra.Command {
	var ns, container, since string
	var limit int
	var previous bool
	c := &cobra.Command{
		Use:   "logs TARGET POD|SERVICE",
		Short: "Logs of a pod (Kubernetes) or a service (Swarm)",
		Example: `  komando cluster logs prod-k8s api-7d9f-x2 --namespace shop --since 10m
  komando cluster logs swarm-manager web -n 100`,
		Args: cobra.ExactArgs(2),
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
				c := "docker service logs --no-trunc --timestamps --tail " + strconv.Itoa(limit)
				if since != "" {
					c += " --since " + sshx.Q(since)
				}
				return runOne(cmd.Context(), "cluster.logs", t.host.Name, c+" "+sshx.Q(args[1])+" 2>&1", false, false)
			}
			return withKube(cmd.Context(), "cluster.logs", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				q := url.Values{"tailLines": {strconv.Itoa(limit)}, "timestamps": {"true"}}
				if container != "" {
					q.Set("container", container)
				}
				if previous {
					q.Set("previous", "true")
				}
				if since != "" {
					d, err := time.ParseDuration(strings.TrimPrefix(since, "-"))
					if err != nil {
						return nil, out.Usage("--since takes a duration like 10m or 2h")
					}
					q.Set("sinceSeconds", strconv.Itoa(int(d.Seconds())))
				}
				space := firstNonEmpty(ns, k.Namespace)
				b, err := k.Do(ctx, "GET", "/api/v1/namespaces/"+url.PathEscape(space)+"/pods/"+url.PathEscape(args[1])+"/log", q, nil, "")
				if err != nil {
					return nil, err
				}
				return logText{Pod: args[1], Namespace: space, Logs: string(b)}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	c.Flags().StringVar(&since, "since", "", "only newer than this, e.g. 10m")
	c.Flags().IntVarP(&limit, "limit", "n", 200, "max lines (from the end)")
	c.Flags().BoolVar(&previous, "previous", false, "the previous run of a restarted container")
	return c
}

type logText struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Logs      string `json:"logs"`
}

func (l logText) Text() string { return l.Logs }

// splitRef parses TYPE/NAME, as in deployment/api.
func splitRef(ref string) (string, string, error) {
	typ, name, ok := strings.Cut(ref, "/")
	if !ok || typ == "" || name == "" {
		return "", "", out.Usage("give TYPE/NAME, e.g. deployment/api")
	}
	return typ, name, nil
}

func clusterRestartCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "restart TARGET TYPE/NAME",
		Short: "Restart a deployment, statefulset or daemonset (rolling), or a Swarm service",
		Example: `  komando cluster restart prod-k8s deployment/api --namespace shop
  komando cluster restart swarm-manager service/web`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			typ, name, err := splitRef(args[1])
			if err != nil {
				return err
			}
			if t.host != nil {
				return runOne(cmd.Context(), "cluster.restart", t.host.Name, "docker service update --force --detach "+sshx.Q(name), false, true)
			}
			return withKube(cmd.Context(), "cluster.restart", t, driver.RiskWrite, map[string]any{"object": args[1]}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, typ)
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "DaemonSet") {
					return nil, out.Usage("restart works on deployments, statefulsets and daemonsets")
				}
				patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339))
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				space := firstNonEmpty(ns, k.Namespace)
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name), q, []byte(patch), "application/strategic-merge-patch+json"); err != nil {
					return nil, err
				}
				return map[string]any{"conn": t.conn.Name, "restarted": args[1], "namespace": space, "dry_run": g.dryRun}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
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
	c := &cobra.Command{
		Use:   "scale TARGET TYPE/NAME REPLICAS",
		Short: "Set the number of replicas (0 stops it: needs --allow-dangerous)",
		Example: `  komando cluster scale prod-k8s deployment/api 3 --namespace shop
  komando cluster scale swarm-manager service/web 4`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[2])
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
			typ, name, err := splitRef(args[1])
			if err != nil {
				return err
			}
			risk := driver.RiskWrite
			if n == 0 {
				risk = driver.RiskDestructive // stopping every replica is an outage
			}
			if t.host != nil {
				if n == 0 && !g.allowDangerous {
					return guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-scale-zero"}, Reasons: []string{"scaling to 0 stops the service"}})
				}
				return runOne(cmd.Context(), "cluster.scale", t.host.Name, "docker service scale --detach "+sshx.Q(name+"="+args[2]), false, true)
			}
			return withKube(cmd.Context(), "cluster.scale", t, risk, map[string]any{"object": args[1], "replicas": n}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, typ)
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				space := firstNonEmpty(ns, k.Namespace)
				body := fmt.Sprintf(`{"spec":{"replicas":%d}}`, n)
				if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, name)+"/scale", q, []byte(body), "application/merge-patch+json"); err != nil {
					return nil, err
				}
				return map[string]any{"conn": t.conn.Name, "scaled": args[1], "replicas": n, "namespace": space, "dry_run": g.dryRun}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
}

func clusterApplyCmd() *cobra.Command {
	var file, ns, stack string
	c := &cobra.Command{
		Use:   "apply TARGET --file FILE",
		Short: "Apply YAML (Kubernetes, server-side; --dry-run asks the server) or deploy a stack (Swarm)",
		Example: `  komando cluster apply prod-k8s --file app.yaml --dry-run
  komando cluster apply prod-k8s --file app.yaml
  komando cluster apply swarm-manager --file compose.yml --stack shop`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return out.Usage("give the YAML with --file")
			}
			b, err := readFileOrStdin(file)
			if err != nil {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "%v", err)
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				if stack == "" {
					return out.Usage("Swarm needs --stack NAME")
				}
				return runFleet(cmd.Context(), "cluster.apply", t.host.Name, "docker stack deploy --detach=true -c - "+sshx.Q(stack), b, execOpts{}, true)
			}
			docs, err := splitYAML(b)
			if err != nil {
				return out.Usage("%s: %v", file, err)
			}
			return withKube(cmd.Context(), "cluster.apply", t, driver.RiskWrite, map[string]any{"file": file, "objects": len(docs)}, func(ctx context.Context, k *kube.Client) (any, error) {
				q := url.Values{"fieldManager": {"komando"}, "force": {"true"}}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				var applied []string
				for _, d := range docs {
					r, err := k.ResourceFor(ctx, d.APIVersion, d.Kind)
					if err != nil {
						return nil, out.Usage("%v", err)
					}
					space := ""
					if r.IsNamespaced() {
						space = firstNonEmpty(d.Namespace, ns, k.Namespace)
					}
					if _, err := k.Do(ctx, "PATCH", r.ObjectPath(space, d.Name), q, d.JSON, "application/apply-patch+yaml"); err != nil {
						return nil, fmt.Errorf("%s/%s: %w", d.Kind, d.Name, err)
					}
					applied = append(applied, strings.ToLower(d.Kind)+"/"+d.Name)
				}
				return map[string]any{"conn": t.conn.Name, "applied": applied, "dry_run": g.dryRun}, nil
			})
		},
	}
	c.Flags().StringVar(&file, "file", "", "YAML file ('-' for stdin)")
	c.Flags().StringVar(&stack, "stack", "", "Swarm: the stack name")
	nsFlags(c, &ns, nil)
	return c
}

type kubeDoc struct {
	APIVersion, Kind, Name, Namespace string
	JSON                              []byte
}

// splitYAML reads a multi-document YAML file into objects.
func splitYAML(b []byte) ([]kubeDoc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var docs []kubeDoc
	for {
		var o map[string]any
		if err := dec.Decode(&o); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		if len(o) == 0 {
			continue
		}
		m, _ := o["metadata"].(map[string]any)
		d := kubeDoc{APIVersion: fmt.Sprint(o["apiVersion"]), Kind: fmt.Sprint(o["kind"]), Name: fmt.Sprint(m["name"])}
		if ns, ok := m["namespace"].(string); ok {
			d.Namespace = ns
		}
		if d.Kind == "<nil>" || d.Name == "<nil>" || d.APIVersion == "<nil>" {
			return nil, fmt.Errorf("every object needs apiVersion, kind and metadata.name")
		}
		var err error
		if d.JSON, err = json.Marshal(o); err != nil {
			return nil, err
		}
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no objects found")
	}
	return docs, nil
}

func clusterRmCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "rm TARGET TYPE NAME",
		Short: "Delete an object (Kubernetes) or a service or stack (Swarm); needs --allow-dangerous",
		Example: `  komando cluster rm prod-k8s pod api-7d9f-x2 --namespace shop --allow-dangerous
  komando cluster rm swarm-manager service web --allow-dangerous`,
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
				typ := strings.TrimSuffix(strings.ToLower(args[1]), "s")
				if typ != "service" && typ != "stack" {
					return out.Usage("Swarm removes a service or a stack")
				}
				if !g.allowDangerous {
					return guardConns(st, nil, driver.Verdict{Risk: driver.RiskDestructive, RuleIDs: []string{"cluster-rm"}, Reasons: []string{"removes " + typ + " " + args[2]}})
				}
				return runOne(cmd.Context(), "cluster.rm", t.host.Name, "docker "+typ+" rm "+sshx.Q(args[2]), false, true)
			}
			return withKube(cmd.Context(), "cluster.rm", t, driver.RiskDestructive, map[string]any{"object": args[1] + "/" + args[2]}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := k.Resource(ctx, args[1])
				if err != nil {
					return nil, out.Usage("%v", err)
				}
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				space := firstNonEmpty(ns, k.Namespace)
				if _, err := k.Do(ctx, "DELETE", r.ObjectPath(space, args[2]), q, nil, ""); err != nil {
					return nil, err
				}
				return map[string]any{"conn": t.conn.Name, "removed": strings.ToLower(r.KindName()) + "/" + args[2], "dry_run": g.dryRun}, nil
			})
		},
	}
	nsFlags(c, &ns, nil)
	return c
}

// classifyKubectl rates a kubectl command by its verb (args[0]) and, where
// the verb alone says too little, its subcommand.
func classifyKubectl(args []string) driver.Risk {
	verb, sub := strings.ToLower(args[0]), ""
	if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	switch {
	case oneOf(verb, "get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions",
		"cluster-info", "events", "diff", "wait"):
		return driver.RiskRead
	case verb == "auth" && oneOf(sub, "can-i", "whoami"):
		return driver.RiskRead
	case verb == "rollout" && oneOf(sub, "status", "history"):
		return driver.RiskRead
	case verb == "config" && oneOf(sub, "view", "get-contexts", "current-context"):
		return driver.RiskRead
	case oneOf(verb, "delete", "drain", "replace", "patch", "taint", "certificate", "cordon", "uncordon", "exec",
		"cp", "attach", "debug", "proxy", "port-forward"):
		return driver.RiskDestructive // exec/cp/debug run anything inside the cluster
	}
	return driver.RiskWrite
}

// classifyDocker rates a docker command on a Swarm manager.
func classifyDocker(args []string) driver.Risk {
	verb, sub := strings.ToLower(args[0]), ""
	if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	group := oneOf(verb, "service", "stack", "node", "secret", "config", "network", "volume", "container", "image", "system", "swarm")
	switch {
	case !group && oneOf(verb, "ps", "images", "info", "version", "inspect", "logs", "stats", "top", "events"):
		return driver.RiskRead
	case group && oneOf(sub, "ls", "ps", "inspect", "logs", "services", "df", "info", "events"):
		return driver.RiskRead
	case oneOf(sub, "rm", "prune", "leave", "demote", "kill") || oneOf(verb, "rm", "rmi", "kill", "prune") ||
		(verb == "swarm" && oneOf(sub, "leave", "init", "join")):
		return driver.RiskDestructive
	}
	return driver.RiskWrite
}

func clusterRunCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "run TARGET -- ARGS...",
		Short: "Run any kubectl (Kubernetes) or docker (Swarm manager) command; read-only unless --write",
		Long: `For Kubernetes, kubectl runs on this computer with the conn's kubeconfig
(a private temporary file) and reaches the API through the conn's --via
path. For Swarm, docker runs on the manager. Commands that change things
need --write; delete, drain and other risky verbs also need
--allow-dangerous.`,
		Example: `  komando cluster run prod-k8s -- get pods -A -o wide
  komando cluster run prod-k8s --write -- rollout undo deployment/api -n shop
  komando cluster run swarm-manager -- service ps web`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			// The command must start with its verb: a leading flag could
			// hide the real verb behind a flag value (-n get delete ...).
			if strings.HasPrefix(args[1], "-") {
				return out.Usage("start with the command (e.g. `-- get pods -n shop`); put flags after it")
			}
			var risk driver.Risk
			if t.host != nil {
				risk = classifyDocker(args[1:])
			} else {
				risk = classifyKubectl(args[1:])
			}
			verb := strings.ToLower(args[1])
			tool := map[bool]string{true: "docker", false: "kubectl"}[t.host != nil]
			// the destructive-command policy sees the words as typed (quoting
			// them for the shell would hide them from its patterns)
			if hits := policy.Check(strings.Join(append([]string{tool}, args[1:]...), " "), st.Settings.ExtraDenyPattern); len(hits) > 0 {
				risk = driver.RiskDestructive
			}
			if risk > driver.RiskRead && !write {
				return out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG", "this changes the cluster; re-run with --write (try --dry-run first)",
					"%q is not a read-only command", verb)
			}
			if t.host != nil {
				line := "docker"
				for _, a := range args[1:] {
					line += " " + sshx.Q(a)
				}
				if risk == driver.RiskDestructive && !g.allowDangerous {
					return guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-run"}, Reasons: []string{"docker " + verb}})
				}
				return runOne(cmd.Context(), "cluster.run", t.host.Name, line, false, risk > driver.RiskRead)
			}
			if _, err := exec.LookPath("kubectl"); err != nil {
				return out.Errf(out.ExitNotFound, "KUBECTL_MISSING", "install kubectl (https://kubernetes.io/docs/tasks/tools/)", "cluster run needs kubectl on this computer")
			}
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-run"}, Reasons: []string{"kubectl " + verb}}); err != nil {
				return err
			}
			return runKubectl(cmd.Context(), st, t.conn, args[1:], risk)
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow commands that change the cluster")
	return c
}

// runKubectl runs kubectl with a private kubeconfig. When the conn has a
// --via path, a local tunnel leads to the API and the kubeconfig points at
// it (keeping the real server name for TLS).
func runKubectl(ctx context.Context, st *store.State, c *store.Conn, args []string, risk driver.Risk) error {
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return err
	}
	defer a.Close()
	cfg, err := kube.Parse([]byte(a.Password))
	if err != nil {
		return out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "%v", err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		return out.Errf(out.ExitUsage, "KUBECONFIG", "", "%v", err)
	}
	if a.Dial != nil {
		u, err := url.Parse(x.Cluster.Server)
		if err != nil {
			return err
		}
		addr := u.Host
		if u.Port() == "" {
			addr += ":443"
		}
		local, stop, err := forwardLocal(ctx, a.Dial, addr)
		if err != nil {
			return err
		}
		defer stop()
		if x.Cluster.TLSServerName == "" {
			x.Cluster.TLSServerName = u.Hostname()
		}
		x.Cluster.Server = "https://" + local
	}
	kc, err := x.Standalone()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "komando-kube-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, kc, 0o600); err != nil {
		return err
	}
	kargs := []string{"--kubeconfig", path, args[0]}
	if g.dryRun && risk > driver.RiskRead {
		// right after the verb, so it can never become an argument of a
		// command run inside a pod (exec ... -- CMD)
		if oneOf(strings.ToLower(args[0]), "exec", "cp", "attach", "debug", "proxy", "port-forward", "run") {
			return out.Usage("kubectl %s cannot be dry-run", args[0])
		}
		kargs = append(kargs, "--dry-run=server")
	}
	kargs = append(kargs, args[1:]...)
	k := exec.CommandContext(ctx, "kubectl", kargs...)
	var stdout, stderr bytes.Buffer
	k.Stdout, k.Stderr = &stdout, &stderr
	if out.P.Format == "text" {
		k.Stdout, k.Stderr, k.Stdin = os.Stdout, os.Stderr, os.Stdin
	}
	runErr := k.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return runErr
		}
	}
	if risk > driver.RiskRead {
		audit(st, "cluster.run", nil, "kubectl "+strings.Join(redactArgs(args), " "), code == 0, map[string]any{"conns": []string{c.Name}, "risk": risk.String()})
	}
	if out.P.Format == "text" {
		if code != 0 {
			return exitCode(out.ExitRemote)
		}
		return nil
	}
	data := map[string]any{"conn": c.Name, "exit_code": code, "stdout": stdout.String(), "stderr": stderr.String()}
	if code != 0 {
		out.P.Print("cluster.run", data, &out.Error{Code: "FAILED", Message: "kubectl exited " + strconv.Itoa(code), Exit: out.ExitRemote})
		return exitCode(out.ExitRemote)
	}
	out.P.Print("cluster.run", data, nil)
	return nil
}

// importKubeconfig makes one k8s conn per context; each context's
// credentials go to the vault as a standalone kubeconfig.
func importKubeconfig(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	cfg, err := kube.Parse(b)
	if err != nil {
		return nil, out.Usage("%s: %v", path, err)
	}
	p := newPlan()
	names := cfg.ContextNames()
	sort.Strings(names)
	for _, n := range names {
		x, err := cfg.Resolve(n)
		if err != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("context %s: %v", n, err))
			continue
		}
		kc, err := x.Standalone()
		if err != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("context %s: %v", n, err))
			continue
		}
		u, err := url.Parse(x.Cluster.Server)
		if err != nil || u.Host == "" {
			p.Notes = append(p.Notes, fmt.Sprintf("context %s: bad server %q", n, x.Cluster.Server))
			continue
		}
		name := p.name(n)
		c := &store.Conn{Name: name, URL: "k8s://" + u.Host, PasswordRef: "secret:" + name + "-kubeconfig"}
		if x.Namespace != "" {
			c.Options = map[string]string{"namespace": x.Namespace}
		}
		p.Secrets[name+"-kubeconfig"] = string(kc)
		p.Conns = append(p.Conns, c)
		if x.User.Exec != nil {
			p.Notes = append(p.Notes, fmt.Sprintf("context %s logs in with %s; komando runs it when needed", n, x.User.Exec.Command))
		}
	}
	return p, nil
}

// redactArgs hides values that may be secrets (--from-literal=k=v,
// --password=..., --token ...) before arguments reach the audit log.
func redactArgs(args []string) []string {
	res := make([]string, len(args))
	hideNext := false
	for i, a := range args {
		low := strings.ToLower(a)
		switch {
		case hideNext:
			res[i], hideNext = "(hidden)", false
		case strings.Contains(low, "literal") || strings.Contains(low, "password") || strings.Contains(low, "token") ||
			strings.Contains(low, "secret"):
			if k, _, ok := strings.Cut(a, "="); ok {
				res[i] = k + "=(hidden)"
			} else {
				res[i], hideNext = a, strings.HasPrefix(a, "-")
			}
		default:
			res[i] = a
		}
	}
	return res
}

// forwardLocal listens on a free local port and forwards each connection
// to addr through dial. stop closes it.
func forwardLocal(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), addr string) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				rc, err := dial(ctx, "tcp", addr)
				if err != nil {
					return
				}
				pipe(c, rc)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }, nil
}
