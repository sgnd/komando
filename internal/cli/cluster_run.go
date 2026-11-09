package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func clusterRmCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "rm TARGET TYPE NAME",
		Short: "Delete an object, service or stack (needs --allow-dangerous)",
		Example: `  komando cluster rm prod-k8s pod api-7d9f-x2 --namespace shop --allow-dangerous
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
		Short: "Run any kubectl or docker command (read-only unless --write)",
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
			return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "a credential plugin only prints a token; check the kubeconfig (if this program is intended, --allow-dangerous lets it run)",
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
