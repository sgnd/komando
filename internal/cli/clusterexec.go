package cli

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/kube"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// cluster exec, shell and forward speak Kubernetes' streaming protocols
// themselves (internal/kube), so kubectl is not needed.

func clusterExecCmd() *cobra.Command {
	var ns, container string
	var readOnly bool
	c := &cobra.Command{
		Use:   "exec TARGET POD|TYPE/NAME -- COMMAND...",
		Short: "Run a command in a pod (not interactive; policy checks it)",
		Long: `Runs COMMAND in the pod (for TYPE/NAME, in one of its pods) and returns its
output. Commands that only look can say so with --read-only: one that
clearly changes something is refused, and protected clusters skip --yes
only for commands komando knows read (cat, ls, printenv ...). For an
interactive shell use ` + "`komando cluster shell TARGET POD`" + `.`,
		Example: `  komando cluster exec prod deploy/api --namespace shop --read-only -- cat /app/config.yml
  komando cluster exec prod api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear`,
		Args: cobra.MinimumNArgs(3),
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
				return out.Usage("on Swarm, run it in the container with `komando docker exec NODE CONTAINER -- ...` on the node that runs the task (`komando cluster describe TARGET service NAME` shows it)")
			}
			inner := strings.Join(args[2:], " ")
			// the policy sees the command as typed, like `exec` on servers
			if err := guard(st, nil, inner, false); err != nil {
				return err
			}
			risk, err := clusterExecRisk(args[2:], readOnly)
			if err != nil {
				return err
			}
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-exec"}, Reasons: []string{"exec in " + args[1]}}); err != nil {
				return err
			}
			if g.dryRun {
				if err := dryRunKubeCheck(t.conn); err != nil { // the login program, as the real run would
					return err
				}
				out.P.Print("cluster.exec", map[string]any{"conn": t.conn.Name, "pod": args[1], "container": container,
					"command": args[2:], "would_run": "exec " + args[1] + " -- " + inner}, nil)
				return nil
			}
			k, done, err := kubeClient(cmd.Context(), st, t.conn)
			if err != nil {
				return err
			}
			defer done()
			space := cmp.Or(ns, k.Namespace)
			pod, err := onePod(cmd.Context(), k, space, args[1])
			if err != nil {
				return kubeErr(err)
			}
			var stdout, stderr bytes.Buffer
			ctx := cmd.Context()
			if g.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, g.timeout)
				defer cancel()
			}
			err = k.Exec(ctx, kube.ExecOptions{Namespace: space, Pod: pod, Container: container, Command: args[2:], Stdout: &stdout, Stderr: &stderr})
			code := 0
			var ee *kube.ExitError
			switch {
			case errors.As(err, &ee):
				code = ee.Code
			case errors.Is(err, context.DeadlineExceeded):
				return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "the command in %s did not end within %s", pod, g.timeout)
			case err != nil:
				return kubeErr(err)
			}
			if risk > driver.RiskRead {
				audit(st, "cluster.exec", nil, inner, code == 0, map[string]any{"conns": []string{t.conn.Name}, "pod": pod, "risk": risk.String()})
			}
			fail := kubectlFailure(code, stderr.String())
			if out.P.Format == "text" {
				fmt.Fprint(os.Stdout, out.SafeText(out.P.Redact(stdout.String())))
				fmt.Fprint(os.Stderr, out.SafeText(out.P.Redact(stderr.String())))
				if fail != nil {
					return exitCode(fail.Exit)
				}
				return nil
			}
			out.P.Print("cluster.exec", map[string]any{"conn": t.conn.Name, "pod": pod, "exit_code": code, "stdout": stdout.String(), "stderr": stderr.String()}, fail)
			if fail != nil {
				return exitCode(fail.Exit)
			}
			return nil
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare that the command only looks (protected clusters: no --yes for commands komando knows read)")
	return c
}

// onePod is the pod a POD or TYPE/NAME stands for: the pod itself, or the
// first running pod of the workload or service (as kubectl picks one).
func onePod(ctx context.Context, k *kube.Client, space, ref string) (string, error) {
	if !strings.Contains(ref, "/") {
		return ref, nil
	}
	pods, err := runningPods(ctx, k, space, ref)
	if err != nil {
		return "", err
	}
	return pods[0], nil
}

func runningPods(ctx context.Context, k *kube.Client, space, ref string) ([]string, error) {
	pods, err := logPods(ctx, k, space, ref, "")
	if err != nil {
		return nil, err
	}
	var running []string
	for _, p := range pods {
		var o struct {
			Status struct{ Phase string } `json:"status"`
		}
		if k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods/"+url.PathEscape(p), nil, &o) == nil && o.Status.Phase == "Running" {
			running = append(running, p)
		}
	}
	if len(running) == 0 {
		return nil, out.Errf(out.ExitNotFound, "K8S_NOT_FOUND", "check them with `komando cluster ls TARGET pods`", "%s has no running pod", ref)
	}
	return running, nil
}

func clusterShellCmd() *cobra.Command {
	var ns, container string
	c := &cobra.Command{
		Use:   "shell TARGET POD|TYPE/NAME [-- COMMAND...]",
		Short: "Interactive shell in a pod (for people), like kubectl exec -it",
		Long: `Opens a terminal in the pod's container: bash when it has one, else sh, or
COMMAND. For people at a terminal; agents use ` + "`komando cluster exec`" + `.
Anything can be typed inside, so a protected cluster asks first.`,
		Example: `  komando cluster shell prod deploy/api --namespace shop
  komando cluster shell prod api-7d9f-x2 -c api -- /bin/ash`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !interactive() {
				return out.Errf(out.ExitUsage, "NEEDS_TERMINAL", "agents and scripts use `komando cluster exec`", "cluster shell is interactive and needs a person at a terminal")
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
				return out.Usage("on Swarm, use `komando docker exec NODE CONTAINER -- sh` on the node that runs the task")
			}
			command := args[2:]
			if len(command) == 0 {
				command = []string{"sh", "-c", "command -v bash >/dev/null 2>&1 && exec bash || exec sh"}
			}
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: driver.RiskWrite, RuleIDs: []string{"cluster-shell"}, Reasons: []string{"shell in " + args[1]}}); err != nil {
				return err
			}
			if g.dryRun {
				if err := dryRunKubeCheck(t.conn); err != nil { // the login program, as the real run would
					return err
				}
				out.P.Print("cluster.shell", map[string]any{"conn": t.conn.Name, "pod": args[1], "container": container, "command": command, "dry_run": true}, nil)
				return nil
			}
			k, done, err := kubeClient(cmd.Context(), st, t.conn)
			if err != nil {
				return err
			}
			defer done()
			space := cmp.Or(ns, k.Namespace)
			pod, err := onePod(cmd.Context(), k, space, args[1])
			if err != nil {
				return kubeErr(err)
			}
			showStatus(statusLine{What: "shell", Target: t.conn.Name, Detail: space + "/" + pod, Route: connRoute(st, t.conn), Protected: protectedConn(st, t.conn)})
			audit(st, "cluster.shell", nil, "", true, map[string]any{"conns": []string{t.conn.Name}, "pod": pod})
			fd := int(os.Stdin.Fd())
			old, err := term.MakeRaw(fd)
			if err != nil {
				return err
			}
			resize := make(chan kube.TermSize, 1)
			if w, h, err := term.GetSize(fd); err == nil {
				resize <- kube.TermSize{Width: uint16(w), Height: uint16(h)}
			}
			winch := make(chan os.Signal, 1)
			stopResize := notifyResize(fd, winch)
			go func() {
				for range winch {
					if w, h, err := term.GetSize(fd); err == nil {
						select {
						case resize <- kube.TermSize{Width: uint16(w), Height: uint16(h)}:
						default:
						}
					}
				}
			}()
			started := time.Now()
			err = k.Exec(context.WithoutCancel(cmd.Context()), kube.ExecOptions{Namespace: space, Pod: pod, Container: container, Command: command,
				Stdin: os.Stdin, Stdout: os.Stdout, TTY: true, Resize: resize})
			stopResize()
			term.Restore(fd, old)
			var ee *kube.ExitError
			switch {
			case errors.As(err, &ee):
				showExit(pod, ee.Code, false, time.Since(started))
				return exitCode(ee.Code)
			case err != nil:
				showExit(pod, 0, true, time.Since(started))
				return kubeErr(err)
			}
			showExit(pod, 0, false, time.Since(started))
			return nil
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	return c
}

func clusterForwardCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "forward TARGET TYPE/NAME [LOCAL:]REMOTE",
		Short: "Reach a pod or service port from this computer (127.0.0.1) until Ctrl-C",
		Long: `Forwards 127.0.0.1:LOCAL on this computer to REMOTE on a pod, deployment or
service, through the conn's --via path. It runs until Ctrl-C (or --timeout).
Only this computer can use it. For a service, REMOTE is the service's port;
komando forwards to the pod's port behind it.`,
		Example: `  komando cluster forward prod svc/api 8080:80 --namespace shop
  komando cluster forward prod deploy/db 15432:5432 --namespace shop
  komando cluster forward prod svc/api :80 --namespace shop   # any free local port`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			local, remote, ok := strings.Cut(args[2], ":")
			if !ok {
				local, remote = args[2], args[2]
			}
			if local == "" {
				local = "0" // :80 picks a free local port, as with kubectl
			}
			for _, p := range []string{local, remote} {
				if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 65535 {
					return out.Usage("ports are written LOCAL:REMOTE, e.g. 8080:80 (or :80 for any free local port)")
				}
			}
			args[2] = local + ":" + remote
			st, err := loadState()
			if err != nil {
				return err
			}
			t, err := resolveCluster(st, args[0])
			if err != nil {
				return err
			}
			if t.host != nil {
				return out.Usage("on Swarm, use `komando tunnel start MANAGER -L LOCAL:SERVICE:PORT` (published ports are on every node)")
			}
			if _, _, err := splitRef(args[1]); err != nil {
				return err
			}
			// raw access to a pod's port gets around every check komando
			// makes on commands (like cluster shell): a protected cluster asks
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: driver.RiskWrite, RuleIDs: []string{"cluster-forward"},
				Reasons: []string{"forward to " + args[1] + ":" + remote}}); err != nil {
				return err
			}
			if g.dryRun {
				if err := dryRunKubeCheck(t.conn); err != nil { // the login program, as the real run would
					return err
				}
				out.P.Print("cluster.forward", map[string]any{"conn": t.conn.Name, "object": args[1], "local": "127.0.0.1:" + local, "remote": remote,
					"would_run": "port-forward --address 127.0.0.1 " + args[1] + " " + local + ":" + remote}, nil)
				return nil
			}
			ctx := cmd.Context()
			if g.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, g.timeout)
				defer cancel()
			}
			k, done, err := kubeClient(ctx, st, t.conn)
			if err != nil {
				return err
			}
			defer done()
			space := cmp.Or(ns, k.Namespace)
			rport, _ := strconv.Atoi(remote)
			pod, port, err := forwardTarget(ctx, k, space, args[1], rport)
			if err != nil {
				return kubeErr(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:"+local)
			if err != nil {
				return out.Errf(out.ExitConflict, "PORT_IN_USE", "pick another LOCAL port", "cannot listen on 127.0.0.1:%s: %v", local, err)
			}
			defer ln.Close()
			go func() { <-ctx.Done(); ln.Close() }()
			audit(st, "cluster.forward", nil, "", true, map[string]any{"conns": []string{t.conn.Name}, "object": args[1], "pod": pod, "port": port,
				"local": ln.Addr().String(), "risk": driver.RiskWrite.String()})
			showStatus(statusLine{What: "forwarding " + ln.Addr().String() + " → " + args[1] + ":" + remote, Target: t.conn.Name,
				Route: connRoute(st, t.conn), Protected: protectedConn(st, t.conn), Tail: "Ctrl-C stops"})
			conns := 0
			for {
				c, err := ln.Accept()
				if err != nil {
					break
				}
				conns++
				go func() {
					if err := k.PortForward(ctx, space, pod, port, c); err != nil && ctx.Err() == nil {
						fmt.Fprintf(os.Stderr, "komando: forward: %v\n", cleanText(err.Error()))
					}
				}()
			}
			out.P.Print("cluster.forward", map[string]any{"conn": t.conn.Name, "local": ln.Addr().String(), "pod": pod, "port": port,
				"connections": conns, "stopped": true}, nil)
			return nil
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}

// forwardTarget is the pod and container port behind ref: a service's
// port becomes its target port (by number, or by name on the pod).
func forwardTarget(ctx context.Context, k *kube.Client, space, ref string, port int) (string, int, error) {
	typ, name, _ := strings.Cut(ref, "/")
	if typ != "svc" && typ != "service" && typ != "services" {
		pod, err := onePod(ctx, k, space, ref)
		return pod, port, err
	}
	var svc struct {
		Spec struct {
			Selector map[string]string `json:"selector"`
			Ports    []struct {
				Port       int `json:"port"`
				TargetPort any `json:"targetPort"`
			} `json:"ports"`
		} `json:"spec"`
	}
	if err := k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/services/"+url.PathEscape(name), nil, &svc); err != nil {
		return "", 0, err
	}
	var target any
	for _, p := range svc.Spec.Ports {
		if p.Port == port {
			target = p.TargetPort
		}
	}
	if target == nil {
		return "", 0, out.Usage("service %s has no port %d", name, port)
	}
	pod, err := onePod(ctx, k, space, ref)
	if err != nil {
		return "", 0, err
	}
	switch v := target.(type) {
	case float64:
		return pod, int(v), nil
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return pod, n, nil
		}
		var p struct {
			Spec struct {
				Containers []struct {
					Ports []struct {
						Name          string `json:"name"`
						ContainerPort int    `json:"containerPort"`
					} `json:"ports"`
				} `json:"containers"`
			} `json:"spec"`
		}
		if err := k.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(space)+"/pods/"+url.PathEscape(pod), nil, &p); err != nil {
			return "", 0, err
		}
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == v {
					return pod, cp.ContainerPort, nil
				}
			}
		}
		return "", 0, out.Usage("pod %s has no port named %q", pod, v)
	}
	return pod, port, nil
}
