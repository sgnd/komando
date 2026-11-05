package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
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
	x, err := kubeContext(c)
	if err != nil {
		return nil, nil, err
	}
	a, err := openAccess(ctx, st, c)
	if err != nil {
		return nil, nil, err
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

// kubeContext reads the conn's kubeconfig from the vault and checks its
// login program (guardKubePlugin), without connecting to anything.
func kubeContext(c *store.Conn) (*kube.Context, error) {
	kc, err := resolvePassword(c)
	if err != nil {
		return nil, err
	}
	cfg, err := kube.Parse([]byte(kc))
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	x, err := cfg.Resolve("")
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "KUBECONFIG", "import it again with `komando import kubeconfig`", "conn %s: %v", c.Name, err)
	}
	if ns := c.Options["namespace"]; ns != "" {
		x.Namespace = ns
	}
	if err := guardKubePlugin(c, x); err != nil {
		return nil, err
	}
	return x, nil
}

// dryRunKubeCheck is for a dry run that stops before it connects (cluster
// exec, shell, forward): what the real run would need for the conn's
// login program still lands in meta.would_be_blocked.
func dryRunKubeCheck(c *store.Conn) error {
	if _, err := kubeContext(c); err != nil && !errors.Is(err, errDryRunStopped) {
		return err
	}
	return nil
}

// errDryRunStopped ends a dry run before it would run something only a
// person may allow (a kubeconfig's login program); the stop is in
// meta.would_be_blocked, and the command prints its plan instead.
var errDryRunStopped = errors.New("dry run stopped before a step that needs a person")

// guardKubePlugin: a kubeconfig credential plugin that komando does not
// make itself runs a program on this computer each time komando logs in,
// like a host's --proxy-command (guardProxyCommand). An AI agent can bring
// one in (import kubeconfig, or a kubeconfig stored with secret set), so
// an agent command that would run it needs a person's yes, unless a person
// trusted this very program for the conn (Conn.TrustedPlugin, set only by
// an import a person made or allowed). The plugin runs only after that.
// People and scripts wired it themselves.
func guardKubePlugin(c *store.Conn, x *kube.Context) error {
	e := x.Plugin()
	if e == nil {
		return nil
	}
	line := pluginLine(e)
	if hits := policy.Check(line, nil); len(hits) > 0 && !dangerOK() {
		stop := out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a credential plugin only prints a token; check the kubeconfig of this conn",
			"the kubeconfig of conn %s logs in with `%s`, which matches destructive rules: %s", c.Name, line, hits[0].Reason)
		if g.dryRun {
			out.P.WouldBlock(stop)
			return errDryRunStopped
		}
		return stop
	}
	if !isAgent() || c.TrustedPlugin != "" && c.TrustedPlugin == pluginTrust(line, x.Cluster.Server) {
		return nil
	}
	what := "the kubeconfig of conn " + c.Name + " runs `" + line + "` on this computer to log in"
	stop := out.Errf(out.ExitPolicy, "SAFETY_SETTING",
		"a program on this computer is outside the agent guard's view: re-run with --yes after the user confirms it (read-only commands ask too). "+
			"To trust it for this conn for good, the user runs `komando import kubeconfig FILE --overwrite` themselves",
		"%s; an AI agent needs a person's yes each time", what)
	if g.dryRun { // a dry run never runs it: --yes is not asked for here
		if !g.yes {
			out.P.WouldBlock(stop)
		}
		return errDryRunStopped
	}
	if safetyApproved[what] || g.yes && personAllowsFor("--yes", what) {
		safetyApproved[what] = true
		return nil
	}
	return stop
}

// pluginTrust is what Conn.TrustedPlugin holds for a login program: a
// hash of its whole line and of the server its token goes to, so any
// change (another program, args, environment or server) asks again.
func pluginTrust(line, server string) string {
	h := sha256.Sum256([]byte(line + "\n" + server))
	return hex.EncodeToString(h[:])
}

// pluginLine is a credential plugin's command line, as it would run, with
// the environment the kubeconfig gives it (PATH=... changes what runs).
// The words stay unquoted, so the destructive-command policy sees them as
// written, as with a --proxy-command.
func pluginLine(e *kube.ExecAuth) string {
	words := []string{}
	for _, kv := range e.Env {
		words = append(words, kv.Name+"="+kv.Value)
	}
	words = append(words, e.Command)
	words = append(words, e.Args...)
	return strings.Join(words, " ")
}

func kubeErr(err error) error {
	var e *kube.APIError
	if errors.As(err, &e) {
		code, exit, hint := "K8S_ERROR", out.ExitRemote, ""
		switch {
		case e.Code == 401 || e.Code == 403:
			code, exit = "K8S_FORBIDDEN", out.ExitConnect
		case e.Code == 404:
			code, exit = "K8S_NOT_FOUND", out.ExitNotFound
		case e.Code == 409:
			code, exit = "K8S_CONFLICT", out.ExitConflict
		case e.Code == 400 && strings.Contains(e.Message, "is not valid for pod"):
			code, exit, hint = "K8S_NOT_FOUND", out.ExitNotFound, "see the pod's containers with `komando cluster describe TARGET pod NAME`"
		case e.Code == 400 || e.Code == 422:
			code, exit, hint = "K8S_INVALID", out.ExitUsage, "the cluster refused it as written: check the label selector (-l) or the object's YAML"
		}
		msg := e.Message
		if outer := err.Error(); outer != e.Error() {
			msg = strings.TrimSuffix(outer, e.Error()) + e.Message // keep "deployment/web: " in front
		}
		return out.Errf(exit, code, hint, "%s", firstNonEmpty(msg, e.Reason))
	}
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe
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
	// under --dry-run every stop only lands in meta.would_be_blocked
	if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster"}, Reasons: []string{name}}); err != nil {
		return err
	}
	k, done, err := kubeClient(ctx, st, t.conn)
	if errors.Is(err, errDryRunStopped) {
		out.P.Print(name, map[string]any{"conn": t.conn.Name, "dry_run": true}, nil)
		return nil
	}
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
	if err != nil && !nilData(res) {
		out.P.Print(name, res, softErr(err)) // what happened before it failed (a rollout that timed out)
		return exitFor(err)
	}
	if err != nil {
		return err
	}
	out.P.Print(name, res, nil)
	return nil
}

// age is a Kubernetes timestamp as a kubectl age (40s, 5m, 3h, 12d).
func age(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	return humanAge(time.Since(t))
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
	c.AddCommand(clusterStatusCmd(), clusterLsCmd(), clusterGetCmd(), clusterDescribeCmd(), clusterEventsCmd(), clusterLogsCmd(), clusterDeployCmd(), clusterHistoryCmd(), clusterRollbackCmd(), clusterExecCmd(), clusterShellCmd(), clusterForwardCmd(), clusterRestartCmd(),
		clusterScaleCmd(), clusterApplyCmd(), clusterRmCmd(), clusterRunCmd())
	return c
}

func clusterStatusCmd() *cobra.Command {
	var ns string
	var wait bool
	c := &cobra.Command{
		Use:   "status TARGET [TYPE/NAME]",
		Short: "Version, nodes, and what is not healthy; with TYPE/NAME, whether it finished rolling out",
		Long: `Without an object: the version, the nodes, and every problem (pods that do not
run, workloads short of replicas, nodes that are not ready; on Swarm, services
short of replicas with their tasks' errors). --namespace limits it to one
namespace. With TYPE/NAME (or TYPE NAME): whether that workload has rolled out;
--wait stays until it has, it fails, or --timeout (default 5m) passes.`,
		Example: `  komando cluster status prod-k8s
  komando cluster status prod-k8s deployment/api --namespace shop --wait
  komando cluster status swarm-manager service/web --wait`,
		Args: cobra.RangeArgs(1, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			if err := noNamespace(t, ns); err != nil {
				return err
			}
			if len(args) > 1 {
				typ, name, err := objectRef(args[1:])
				if err != nil {
					return err
				}
				return rolloutStatus(cmd.Context(), t, typ, name, ns, wait)
			}
			if wait {
				return out.Usage("--wait needs an object: `cluster status %s deployment/NAME --wait`", args[0])
			}
			if t.host != nil {
				res, err := swarmStatus(cmd.Context(), t)
				if err != nil {
					return err
				}
				out.P.Print("cluster.status", res, nil)
				return nil
			}
			return withKube(cmd.Context(), "cluster.status", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				return kubeStatus(ctx, k, t.conn.Name, ns)
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

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
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

// maskObject hides from an AI agent (out.P.Mask) what output masking
// cannot see once an object is printed whole: a Secret's values, and the
// values of env vars named like secrets (hideSecretEnv).
func maskObject(o map[string]any) {
	if !out.P.Mask {
		return
	}
	redact(o)
	hideSecretEnv(o)
}

// refuseHidden stops objects that still hold a value komando hid from an
// agent ([hidden] from maskObject or output masking, "(hidden)" from
// redact): sending them would write that text over the real value, the
// usual round trip being `get -o yaml`, an edit, then apply.
func refuseHidden(docs []kubeDoc) error {
	for _, d := range docs {
		var o any
		if json.Unmarshal(d.JSON, &o) == nil && holdsHidden(o) {
			return out.Errf(out.ExitUsage, "HIDDEN_VALUE",
				"leave the hidden entries out of the file (or use valueFrom.secretKeyRef), or change only what you need with `cluster run TARGET --write -- set image|patch ...`",
				"%s/%s holds a value komando hid from you ([hidden] or (hidden)); sending it would write that text over the real value", strings.ToLower(d.Kind), d.Name)
		}
	}
	return nil
}

func holdsHidden(v any) bool {
	switch x := v.(type) {
	case string:
		return out.HasHidden(x) || x == "(hidden)" || strings.HasPrefix(x, "(hidden, ")
	case map[string]any:
		for k, c := range x {
			if out.HasHidden(k) || holdsHidden(c) {
				return true
			}
		}
	case []any:
		for _, c := range x {
			if holdsHidden(c) {
				return true
			}
		}
	}
	return false
}

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// hideSecretEnv hides the value of every {name, value} pair whose name
// says it is a secret ({name: DB_PASSWORD, value: x} in a container's env,
// an Authorization header in a probe), also in the copy kubectl keeps in
// the last-applied-configuration annotation. Text masking sees NAME=value
// but not a name and a value in two fields. valueFrom (a reference) stays.
func hideSecretEnv(v any) {
	switch x := v.(type) {
	case map[string]any:
		if n, ok := x["name"].(string); ok {
			if val, ok := x["value"].(string); ok && val != "" && secretValue(n, val) {
				x["value"] = out.Hidden
			}
		}
		if s, ok := x[lastApplied].(string); ok {
			var cfg any
			if json.Unmarshal([]byte(s), &cfg) == nil {
				hideSecretEnv(cfg)
				if b, err := json.Marshal(cfg); err == nil {
					x[lastApplied] = string(b)
				}
			}
		}
		for _, c := range x {
			hideSecretEnv(c)
		}
	case []any:
		for _, c := range x {
			hideSecretEnv(c)
		}
	}
}

// secretValue: the NAME=value line of this pair has its value masked, so
// a {name, value} pair is hidden by exactly the same rule (true, a path or
// a placeholder stays, as in text).
func secretValue(name, val string) bool {
	line := name + "=" + val
	return out.MaskSecrets(line) != line
}

func clusterLsCmd() *cobra.Command {
	var ns, selector string
	var all bool
	var limit int
	c := &cobra.Command{
		Use:   "ls TARGET TYPE",
		Short: "List pods, deployments, services, nodes, ... (Swarm: services, tasks, nodes, stacks)",
		Example: `  komando cluster ls prod-k8s pods -n shop
  komando cluster ls prod-k8s deploy -A
  komando cluster ls swarm-manager services
  komando cluster ls swarm-manager tasks -n 20`,
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
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				kind := swarmKind(args[1])
				if kind == "" {
					return out.Usage("Swarm lists services (svc), tasks, nodes or stacks; %q is none of them", args[1])
				}
				res, err := swarmList(cmd.Context(), t, kind, selector, limit)
				if err != nil {
					return err
				}
				out.P.Print("cluster.ls", res, nil)
				return nil
			}
			return withKube(cmd.Context(), "cluster.ls", t, driver.RiskRead, nil, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, args[1])
				if err != nil {
					return nil, err
				}
				space := firstNonEmpty(ns, k.Namespace)
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
			})
		},
	}
	nsFlags(c, &ns, &all, &limitOpt{&limit, 500, "max items"})
	c.Flags().StringVarP(&selector, "selector", "l", "", "only objects with these labels, e.g. app=api or 'tier in (web,api)'")
	return c
}

func clusterGetCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "get TARGET TYPE NAME",
		Short: "Show one object in full (Secret values are hidden); TYPE/NAME works too",
		Example: `  komando cluster get prod-k8s deployment api -n shop
  komando cluster get prod-k8s deployment.apps/api -n shop
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
				if err := k.Get(ctx, r.ObjectPath(firstNonEmpty(ns, k.Namespace), name), nil, &o); err != nil {
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
		Example: `  komando cluster restart prod-k8s deployment/api -n shop --wait
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
			return withKube(cmd.Context(), "cluster.restart", t, driver.RiskWrite, map[string]any{"object": typ + "/" + name}, func(ctx context.Context, k *kube.Client) (any, error) {
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
				space := firstNonEmpty(ns, k.Namespace)
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
		Example: `  komando cluster scale prod-k8s deployment/api 3 -n shop --wait
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
			return withKube(cmd.Context(), "cluster.scale", t, risk, map[string]any{"object": typ + "/" + name, "replicas": n}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				if !oneOf(r.KindName(), "Deployment", "StatefulSet", "ReplicaSet", "ReplicationController") {
					return nil, out.Usage("scale works on deployments, statefulsets and replicasets, not %s", strings.ToLower(r.KindName())+"s")
				}
				space := firstNonEmpty(ns, k.Namespace)
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

func clusterApplyCmd() *cobra.Command {
	var file, ns, stack string
	c := &cobra.Command{
		Use:   "apply TARGET --file FILE",
		Short: "Apply YAML (Kubernetes, server-side; --dry-run asks the server) or deploy a stack (Swarm)",
		Long: `Kubernetes: applies every object in FILE server-side and says per object
whether it was created, configured or unchanged. --dry-run asks the server
what would change and shows it as a diff (Secret values stay hidden; a
changed value shows as "(hidden, changed)"). Objects without a namespace go
to --namespace; one that names another namespace is refused.

Swarm: deploys FILE (a compose file) as the stack --stack; --dry-run checks
the file with ` + "`docker stack config`" + ` on the manager.`,
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
				return localFileErr("FILE_NOT_FOUND", err, "")
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
				if err := noNamespace(t, ns); err != nil {
					return err
				}
				if stack == "" {
					return out.Usage("Swarm needs --stack NAME")
				}
				return swarmApply(cmd.Context(), t, stack, b)
			}
			if stack != "" {
				return out.Usage("--stack is for Swarm; Kubernetes objects take their namespace from the file or --namespace")
			}
			docs, err := splitYAML(b)
			if err != nil {
				return out.Usage("%s: %v", file, err)
			}
			if err := refuseHidden(docs); err != nil {
				return err
			}
			for _, d := range docs {
				if d.Namespace != "" && ns != "" && d.Namespace != ns {
					return out.Usage("%s/%s is in namespace %s in the file, not %s from --namespace: leave out --namespace or change the file", strings.ToLower(d.Kind), d.Name, d.Namespace, ns)
				}
			}
			return withKube(cmd.Context(), "cluster.apply", t, driver.RiskWrite, map[string]any{"file": file, "objects": len(docs)}, func(ctx context.Context, k *kube.Client) (any, error) {
				return kubeApply(ctx, k, t.conn.Name, docs, ns)
			})
		},
	}
	c.Flags().StringVar(&file, "file", "", "YAML file ('-' for stdin)")
	c.Flags().StringVar(&stack, "stack", "", "Swarm: the stack name")
	nsFlags(c, &ns, nil, nil)
	return c
}

// kubeApply applies docs server-side (a dry run asks the server only) and
// reports per object what happened, or would.
func kubeApply(ctx context.Context, k *kube.Client, conn string, docs []kubeDoc, ns string) (any, error) {
	q := url.Values{"fieldManager": {"komando"}, "force": {"true"}}
	if g.dryRun {
		q.Set("dryRun", "All")
	}
	res := applyData{Conn: conn, DryRun: g.dryRun, Objects: []objectChange{}}
	creates := map[string]bool{} // namespaces this file creates
	for _, d := range docs {
		r, err := k.ResourceFor(ctx, d.APIVersion, d.Kind)
		if err != nil {
			return nil, out.Usage("%v", err)
		}
		space := ""
		if r.IsNamespaced() {
			space = firstNonEmpty(d.Namespace, ns, k.Namespace)
		}
		path := r.ObjectPath(space, d.Name)
		name := strings.ToLower(d.Kind) + "/" + d.Name
		// the live object, to say what changes
		before, err := k.Do(ctx, "GET", path, nil, nil, "")
		var ae *kube.APIError
		if err != nil && !(errors.As(err, &ae) && ae.Code == 404) {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if g.dryRun && before == nil && creates[space] {
			// the server cannot dry-run into a namespace that does not exist yet
			res.Objects = append(res.Objects, objectChange{Object: name, Namespace: space, Action: "create", Note: "in namespace " + space + ", which this file creates"})
			continue
		}
		after, err := k.Do(ctx, "PATCH", path, q, d.JSON, "application/apply-patch+yaml")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if d.Kind == "Namespace" && before == nil {
			creates[d.Name] = true
		}
		c := diffObject(name, before, after)
		c.Namespace = space
		if !g.dryRun {
			c.Diff = ""
			c.Action = map[string]string{"create": "created", "change": "configured", "none": "unchanged"}[c.Action]
		}
		res.Objects = append(res.Objects, c)
	}
	return res, nil
}

// applyData is `cluster apply`: what happened to each object (created,
// configured, unchanged), or with --dry-run what would (create, change,
// none) and the diff.
type applyData struct {
	Conn    string         `json:"conn"`
	DryRun  bool           `json:"dry_run"`
	Objects []objectChange `json:"-"`
}

func (a applyData) MarshalJSON() ([]byte, error) {
	names := make([]string, len(a.Objects))
	for i, o := range a.Objects {
		names[i] = o.Object
	}
	m := map[string]any{"conn": a.Conn, "dry_run": a.DryRun}
	if a.DryRun {
		m["would_apply"], m["changes"] = names, a.Objects
	} else {
		m["applied"], m["objects"] = names, a.Objects
	}
	return json.Marshal(m)
}

func (a applyData) Text() string {
	var b strings.Builder
	words := map[string]string{"create": "would be created", "change": "would change", "none": "unchanged"}
	for _, o := range a.Objects {
		what := o.Action
		if a.DryRun {
			what = words[o.Action]
		}
		line := o.Object
		if o.Namespace != "" {
			line += " (" + o.Namespace + ")"
		}
		fmt.Fprintf(&b, "%s %s\n", line, what)
		if o.Note != "" {
			fmt.Fprintf(&b, "  note: %s\n", o.Note)
		}
		if o.Diff != "" && o.Action != "create" {
			b.WriteString(indentText(o.Diff, "    "))
		}
	}
	return b.String()
}

// objectChange is one object in `cluster apply`: what the server did or
// would do with it, and with --dry-run the difference as a unified diff.
type objectChange struct {
	Object    string `json:"object"`
	Namespace string `json:"namespace,omitempty"`
	Action    string `json:"action"` // create | change | none (dry run); created | configured | unchanged
	Diff      string `json:"diff,omitempty"`
	Note      string `json:"note,omitempty"`
}

func diffObject(name string, before, after []byte) objectChange {
	c := objectChange{Object: name, Action: "change"}
	parse := func(b []byte) map[string]any {
		var o map[string]any
		if len(b) == 0 || json.Unmarshal(b, &o) != nil {
			return nil
		}
		delete(o, "status")
		if m, ok := o["metadata"].(map[string]any); ok {
			for _, f := range []string{"managedFields", "resourceVersion", "generation", "uid", "creationTimestamp", "selfLink"} {
				delete(m, f)
			}
			if a, ok := m["annotations"].(map[string]any); ok {
				delete(a, "kubectl.kubernetes.io/last-applied-configuration")
				if len(a) == 0 {
					delete(m, "annotations")
				}
			}
		}
		return o
	}
	old, upd := parse(before), parse(after)
	switch {
	case before == nil:
		c.Action = "create"
	case yamlText(old) == yamlText(upd): // compared with Secret values, so a changed value counts
		c.Action = "none"
		return c
	}
	hideSecretValues(old, upd) // Secret values never reach the output, not even in a diff
	if out.P.Mask {
		hideSecretEnv(old)
		hideSecretEnv(upd)
	}
	c.Diff = unifiedDiff(yamlText(old), yamlText(upd), 3)
	return c
}

// hideSecretValues replaces a Secret's values with markers that still say
// which keys changed: (hidden), (hidden, changed), (hidden, new).
func hideSecretValues(old, upd map[string]any) {
	isSecret := func(o map[string]any) bool { return o != nil && o["kind"] == "Secret" }
	if !isSecret(old) && !isSecret(upd) {
		return
	}
	for _, f := range []string{"data", "stringData"} {
		od, _ := old[f].(map[string]any)
		nd, _ := upd[f].(map[string]any)
		for k, v := range nd {
			ov, had := od[k]
			switch {
			case !had && old != nil:
				nd[k] = "(hidden, new)"
			case had && fmt.Sprint(ov) != fmt.Sprint(v):
				nd[k] = "(hidden, changed)"
			default:
				nd[k] = "(hidden)"
			}
		}
		for k := range od {
			od[k] = "(hidden)"
		}
	}
}

// yamlText is o as YAML with 2-space indents, like kubectl prints it.
func yamlText(o map[string]any) string {
	if o == nil {
		return ""
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	_ = enc.Encode(o)
	_ = enc.Close()
	return b.String()
}

// swarmApply deploys a compose file as a stack; --dry-run checks the file
// with `docker stack config` and names the services it would make.
func swarmApply(ctx context.Context, t clusterTarget, stack string, file []byte) error {
	line := "docker stack deploy --detach=true -c - " + sshx.Q(stack) + " 2>&1"
	if g.dryRun {
		st, err := loadState()
		if err != nil {
			return err
		}
		if err := guard(st, []*store.Host{t.host}, line, true); err != nil {
			return err
		}
		res := map[string]any{"host": t.host.Name, "stack": stack, "dry_run": true, "would_run": line}
		cfg, err := swarmExec(ctx, st, t, "docker stack config -c - 2>&1", file)
		if err != nil {
			msg := toErr(err).Message
			if strings.Contains(msg, "unknown command") || strings.Contains(msg, "is not a docker command") {
				res["checked"] = false // docker before 23 has no stack config
				out.P.Print("cluster.apply", res, nil)
				return nil
			}
			return out.Usage("the compose file is not valid: %s", msg)
		}
		var c struct {
			Services map[string]any `yaml:"services"`
		}
		_ = yaml.Unmarshal([]byte(cfg), &c)
		var svcs []string
		for n := range c.Services {
			svcs = append(svcs, "service/"+stack+"_"+n)
		}
		sort.Strings(svcs)
		res["checked"], res["would_apply"] = true, svcs
		out.P.Print("cluster.apply", res, nil)
		return nil
	}
	s, _, err := swarmDo(ctx, "cluster.apply", t, line, file, driver.RiskWrite, line)
	if err != nil {
		return err
	}
	objs := []map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && (f[0] == "Creating" || f[0] == "Updating") {
			act := map[string]string{"Creating": "created", "Updating": "configured"}[f[0]]
			objs = append(objs, map[string]string{"object": f[1] + "/" + f[2], "action": act})
		}
	}
	out.P.Print("cluster.apply", map[string]any{"host": t.host.Name, "stack": stack, "objects": objs, "output": s}, nil)
	return nil
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
		if d.Kind == "<nil>" || d.Name == "<nil>" || d.APIVersion == "<nil>" || d.Name == "" {
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
		Example: `  komando cluster rm prod-k8s pod api-7d9f-x2 -n shop --allow-dangerous
  komando cluster rm swarm-manager service/web --allow-dangerous`,
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
				kind := swarmKind(typ)
				if kind != "service" && kind != "stack" {
					return out.Usage("Swarm removes a service or a stack")
				}
				line := "docker " + kind + " rm " + sshx.Q(name)
				if kind == "service" {
					if _, err := swarmInspect(cmd.Context(), t, name); err != nil {
						return err
					}
				} else if err := swarmStackExists(cmd.Context(), t, name); err != nil {
					return err // stack rm of a missing stack says "Nothing found" and exits 0
				}
				_, ran, err := swarmDo(cmd.Context(), "cluster.rm", t, line, nil, driver.RiskDestructive, "removes "+kind+" "+name)
				if err != nil {
					return err
				}
				res := map[string]any{"host": t.host.Name, "removed": kind + "/" + name}
				if !ran {
					res = map[string]any{"host": t.host.Name, "would_remove": kind + "/" + name, "dry_run": true, "would_run": line}
				}
				out.P.Print("cluster.rm", res, nil)
				return nil
			}
			return withKube(cmd.Context(), "cluster.rm", t, driver.RiskDestructive, map[string]any{"object": typ + "/" + name}, func(ctx context.Context, k *kube.Client) (any, error) {
				r, err := resource(ctx, k, typ)
				if err != nil {
					return nil, err
				}
				q := url.Values{}
				if g.dryRun {
					q.Set("dryRun", "All")
				}
				space := firstNonEmpty(ns, k.Namespace)
				if _, err := k.Do(ctx, "DELETE", r.ObjectPath(space, name), q, nil, ""); err != nil {
					return nil, err
				}
				return map[string]any{"conn": t.conn.Name, "removed": kindRef(r, name), "dry_run": g.dryRun}, nil
			})
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}

// kubectlForbidden are flags that would point kubectl at another cluster or
// identity than the conn's (sending the conn's credentials elsewhere), or
// undo komando's own --dry-run. They are refused in `cluster run`.
var kubectlForbidden = []string{"--kubeconfig", "--server", "-s", "--token", "--context", "--cluster", "--user",
	"--certificate-authority", "--client-certificate", "--client-key", "--insecure-skip-tls-verify",
	"--tls-server-name", "--username", "--password", "--as", "--as-group", "--as-uid", "--dry-run"}

func checkKubectlFlags(args []string) error {
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if oneOf(name, kubectlForbidden...) {
			return out.Usage("%s is not allowed in cluster run: the conn decides the cluster and identity (and komando adds --dry-run itself)", name)
		}
		if a == "--" {
			break // what follows belongs to a command run in a pod
		}
	}
	return nil
}

// hasFlag reports whether args (up to "--") contain one of the flags.
func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if name, _, _ := strings.Cut(a, "="); oneOf(name, flags...) {
			return true
		}
	}
	return false
}

// classifyKubectl rates a kubectl command by its verb (args[0]), its
// subcommand and the flags that change what it does.
func classifyKubectl(args []string) driver.Risk {
	verb, sub := strings.ToLower(args[0]), ""
	if a, err := parseKargs(args); err == nil {
		if len(a.pos) > 0 {
			sub = strings.ToLower(a.pos[0]) // what kctl runs, flags first or not (create -n x token)
		}
	} else if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	joined := " " + strings.Join(args, " ") + " "
	switch {
	case verb == "config":
		if oneOf(sub, "get-contexts", "current-context") {
			return driver.RiskRead
		}
		return driver.RiskDestructive // config view --raw prints the credentials
	case verb == "get" && getsSecretValues(args[1:]) && !out.P.Mask:
		return driver.RiskDestructive // -o yaml/json/jsonpath on Secrets prints their values (an agent sees them hidden: maskObject)
	case oneOf(verb, "get", "describe", "logs", "top", "explain", "version", "api-resources", "api-versions",
		"cluster-info", "events", "diff", "wait"):
		return driver.RiskRead
	case verb == "auth" && oneOf(sub, "can-i", "whoami"):
		return driver.RiskRead
	case verb == "rollout" && oneOf(sub, "status", "history"):
		return driver.RiskRead
	case oneOf(verb, "delete", "drain", "replace", "patch", "edit", "taint", "certificate", "cordon", "uncordon",
		"exec", "cp", "attach", "debug", "proxy", "port-forward"):
		return driver.RiskDestructive // exec/cp/debug run anything inside the cluster; edit patches like patch
	case verb == "apply" && hasFlag(args, "--prune", "--force"),
		verb == "scale" && scalesToZero(args),
		verb == "create" && oneOf(sub, "clusterrolebinding", "rolebinding", "token", "clusterrole"),
		verb == "set" && sub == "subject",
		verb == "run" && (hasFlag(args, "--overrides", "--privileged") || strings.Contains(joined, "hostPID")):
		return driver.RiskDestructive // deletes, outages, or more rights than the conn has
	}
	return driver.RiskWrite
}

// scalesToZero: the replica count kctl would send (the last --replicas,
// read as a number the way kctl reads it: -0 and 00 are 0) stops the
// workload, or cannot be read at all.
func scalesToZero(args []string) bool {
	a, err := parseKargs(args)
	if err != nil {
		return true
	}
	n, err := strconv.Atoi(a.val("replicas"))
	return err != nil || n <= 0
}

// serverDryRun reports whether kctl sends this command to the server with
// dryRun=All, so --dry-run can run it: the server checks the change and
// keeps nothing. Any other command that is not a read would really happen
// (exec, cp, a token), or would print what --dry-run must not reveal (a
// Secret's values, the kubeconfig).
func serverDryRun(args []string) bool {
	a, err := parseKargs(args)
	if err != nil {
		return false
	}
	sub := ""
	if len(a.pos) > 0 {
		sub = strings.ToLower(a.pos[0])
	}
	switch a.verb {
	case "apply", "diff", "replace", "delete", "patch", "label", "annotate", "scale", "set", "cordon", "uncordon", "drain", "taint", "certificate":
		return true
	case "create":
		return sub != "token" || len(a.vals["filename"]) > 0 // a TokenRequest makes a real token
	case "rollout":
		return oneOf(sub, "restart", "pause", "resume", "undo")
	}
	return false
}

// getsSecretValues reports whether `kubectl get` args ask for Secrets with
// an output format that includes their data. The default table and -o
// wide/name show only names and key counts.
func getsSecretValues(args []string) bool {
	secrets, values := false, false
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(args[i])
		format := ""
		switch {
		case a == "-o" || a == "--output":
			if i+1 < len(args) {
				format = strings.ToLower(args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--output="):
			format = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o"):
			format = strings.TrimPrefix(strings.TrimPrefix(a, "-o"), "=")
		case strings.HasPrefix(a, "-"):
			continue
		default:
			for _, r := range strings.Split(a, ",") {
				r, _, _ = strings.Cut(r, "/")
				if oneOf(r, "secret", "secrets") || strings.HasPrefix(r, "secrets.") || strings.HasPrefix(r, "secret.") {
					secrets = true
				}
			}
		}
		if format != "" && !oneOf(format, "wide", "name") {
			values = true
		}
	}
	return secrets && values
}

func clusterRunCmd() *cobra.Command {
	var write bool
	c := &cobra.Command{
		Use:   "run TARGET -- ARGS...",
		Short: "Run any kubectl (Kubernetes) or docker (Swarm manager) command; read-only unless --write",
		Long: `For Kubernetes, komando runs the kubectl command itself (no kubectl
needed) and reaches the API through the conn's --via path: get (tables,
wide, name, json, yaml, jsonpath, custom-columns, -w), describe, logs,
events, top, explain, version, api-resources, api-versions, cluster-info,
auth can-i/whoami, wait, rollout, apply, diff, create, replace, delete,
patch, label, annotate, scale, set image, cordon, uncordon, drain, taint,
run, exec, cp, debug, certificate and config. For Swarm, docker runs on the
manager. Commands that change things need --write; delete, drain and other
risky verbs also need --allow-dangerous.`,
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
				if err := checkKubectlFlags(args[1:]); err != nil {
					return err
				}
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
				if err := policyStop(out.Errf(out.ExitPolicy, "WRITE_REQUIRES_FLAG", "this changes the cluster; re-run with --write (try --dry-run first)",
					"%q is not a read-only command", verb)); err != nil {
					return err
				}
			}
			if t.host != nil {
				line := "docker " + quoteAll(args[1:])
				if risk == driver.RiskDestructive && !dangerOK() {
					if err := guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-run"}, Reasons: []string{"docker " + verb}}); err != nil {
						return err
					}
				}
				return runOne(cmd.Context(), "cluster.run", t.host.Name, line, false, risk > driver.RiskRead)
			}
			// under --dry-run every stop only lands in meta.would_be_blocked
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-run"}, Reasons: []string{"kubectl " + verb}}); err != nil {
				return err
			}
			plan := map[string]any{"conn": t.conn.Name, "dry_run": true, "would_run": "kubectl " + strings.Join(redactArgs(args[1:]), " ")}
			if g.dryRun && risk > driver.RiskRead && !serverDryRun(args[1:]) {
				// the server cannot dry-run it: show it, run nothing
				out.P.Print("cluster.run", plan, nil)
				return nil
			}
			// a watch (-w, logs -f) ends at --timeout like every command
			ctx, cancel := context.WithTimeout(cmd.Context(), cmdTimeout(st))
			defer cancel()
			k, done, err := kubeClient(ctx, st, t.conn)
			if errors.Is(err, errDryRunStopped) {
				out.P.Print("cluster.run", plan, nil)
				return nil
			}
			if err != nil {
				return err
			}
			defer done()
			code, stdout, stderr, stop := runKctlLive(ctx, k, t.conn.Name, args[1:], printLogLine)
			if stop != nil { // komando's own stop, before anything was sent
				if g.dryRun && stop.Exit == out.ExitPolicy {
					out.P.WouldBlock(stop)
					out.P.Print("cluster.run", plan, nil)
					return nil
				}
				return stop
			}
			if risk > driver.RiskRead {
				audit(st, "cluster.run", nil, "kubectl "+strings.Join(redactArgs(args[1:]), " "), code == 0, map[string]any{"conns": []string{t.conn.Name}, "risk": risk.String()})
			}
			fail := kubectlFailure(code, stderr)
			if out.P.Format == "text" {
				fmt.Fprint(os.Stdout, out.SafeText(out.P.Redact(stdout)))
				fmt.Fprint(os.Stderr, out.SafeText(out.P.Redact(stderr)))
				if fail != nil {
					return exitCode(fail.Exit)
				}
				return nil
			}
			out.P.Print("cluster.run", map[string]any{"conn": t.conn.Name, "exit_code": code, "stdout": stdout, "stderr": stderr}, fail)
			if fail != nil {
				return exitCode(fail.Exit)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&write, "write", false, "allow commands that change the cluster")
	return c
}

// kubectlFailure is the error for a kubectl-style exit code: nil when it worked,
// not found (3) when the server said NotFound, else remote (5).
func kubectlFailure(code int, stderr string) *out.Error {
	if code == 0 {
		return nil
	}
	msg := strings.TrimSpace(stderr)
	if i := strings.LastIndex(msg, "\n"); i >= 0 && strings.Contains(msg[i:], "Error") {
		msg = strings.TrimSpace(msg[i:])
	}
	if strings.Contains(stderr, "(NotFound)") || strings.Contains(stderr, "not found") {
		msg = strings.TrimPrefix(msg, "Error from server (NotFound): ")
		return &out.Error{Code: "K8S_NOT_FOUND", Message: firstNonEmpty(msg, "not found"), Exit: out.ExitNotFound,
			Hint: "list what exists with `komando cluster ls TARGET TYPE`"}
	}
	return &out.Error{Code: "FAILED", Message: "kubectl exited " + strconv.Itoa(code) + firstNonEmpty(": "+firstLine(msg), ""), Exit: out.ExitRemote}
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
		if err := guardKubeImport(n, x); err != nil {
			return nil, err
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
		if e := x.Plugin(); e != nil {
			// a person imported it, or allowed it (guardKubeImport): agents
			// may run this program for this conn without asking again
			c.TrustedPlugin = pluginTrust(pluginLine(e), x.Cluster.Server)
			p.Notes = append(p.Notes, fmt.Sprintf("context %s (imported) logs in by running `%s` on this computer for every cluster command", n, pluginLine(e)))
		}
	}
	return p, nil
}

// guardKubeImport: an AI agent importing a kubeconfig that runs a program
// on this computer to log in (guardKubePlugin), or that sends a file of
// this computer to the server as its token (tokenFile), needs a person's
// yes, as for a host's --proxy-command. Under --dry-run the stop is only
// reported.
func guardKubeImport(name string, x *kube.Context) error {
	if e := x.Plugin(); e != nil {
		line := pluginLine(e)
		if hits := policy.Check(line, nil); len(hits) > 0 && !dangerOK() {
			return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a credential plugin only prints a token; check the kubeconfig",
				"context %s logs in with `%s`, which matches destructive rules: %s", name, line, hits[0].Reason))
		}
		if isAgent() {
			if err := guardSafety("context " + name + " runs `" + line + "` on this computer whenever komando logs in, also for AI agents' later commands"); err != nil {
				return err
			}
		}
	}
	if f := x.User.TokenFile; f != "" && isAgent() {
		return guardSafety("context " + name + " sends the file " + f + " from this computer to its server as the login token")
	}
	return nil
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

// nilData is true for nil and for a nil map, slice or pointer in an any.
func nilData(v any) bool {
	if v == nil {
		return true
	}
	switch r := reflect.ValueOf(v); r.Kind() {
	case reflect.Map, reflect.Slice, reflect.Pointer:
		return r.IsNil()
	}
	return false
}
