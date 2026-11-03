package cli

import (
	"context"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func needKubectl() error {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return out.Errf(out.ExitNotFound, "KUBECTL_MISSING", "install kubectl (https://kubernetes.io/docs/tasks/tools/)", "this command needs kubectl on this computer")
	}
	return nil
}

func clusterExecCmd() *cobra.Command {
	var ns, container string
	var readOnly bool
	c := &cobra.Command{
		Use:   "exec TARGET POD|TYPE/NAME -- COMMAND...",
		Short: "Run a command in a pod (not interactive); the destructive-command policy checks it",
		Long: `Runs COMMAND in the pod (for TYPE/NAME, in one of its pods) and returns its
output. Commands that only look can say so with --read-only, so protected
clusters do not ask for --yes. For an interactive shell use
` + "`komando cluster run TARGET --write -- exec -it POD -- sh`" + ` in a terminal.`,
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
			risk := driver.RiskWrite
			if readOnly {
				risk = driver.RiskRead
			}
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-exec"}, Reasons: []string{"exec in " + args[1]}}); err != nil {
				return err
			}
			kargs := []string{"exec", args[1]}
			if ns := firstNonEmpty(ns, t.conn.Options["namespace"]); ns != "" {
				kargs = append(kargs, "-n", ns)
			}
			if container != "" {
				kargs = append(kargs, "-c", container)
			}
			kargs = append(append(kargs, "--"), args[2:]...)
			if g.dryRun {
				out.P.Print("cluster.exec", map[string]any{"conn": t.conn.Name, "would_run": "kubectl " + strings.Join(kargs, " ")}, nil)
				return nil
			}
			if err := needKubectl(); err != nil {
				return err
			}
			return runKubectl(cmd.Context(), st, t.conn, "cluster.exec", kargs, risk, false)
		},
	}
	nsFlags(c, &ns, nil, nil)
	c.Flags().StringVarP(&container, "container", "c", "", "container in the pod")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare that the command only looks (no --yes on protected clusters)")
	return c
}

func clusterForwardCmd() *cobra.Command {
	var ns string
	c := &cobra.Command{
		Use:   "forward TARGET TYPE/NAME [LOCAL:]REMOTE",
		Short: "Reach a pod or service port from this computer (127.0.0.1) until Ctrl-C",
		Long: `Forwards 127.0.0.1:LOCAL on this computer to REMOTE on a pod, deployment or
service, through the conn's --via path. It runs until Ctrl-C (or --timeout).
Only this computer can use it.`,
		Example: `  komando cluster forward prod svc/api 8080:80 --namespace shop
  komando cluster forward prod deploy/db 15432:5432 --namespace shop`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			local, remote, ok := strings.Cut(args[2], ":")
			if !ok {
				local, remote = args[2], args[2]
			}
			for _, p := range []string{local, remote} {
				if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 65535 {
					return out.Usage("ports are written LOCAL:REMOTE, e.g. 8080:80")
				}
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
				return out.Usage("on Swarm, use `komando tunnel start MANAGER -L LOCAL:SERVICE:PORT` (published ports are on every node)")
			}
			if _, _, err := splitRef(args[1]); err != nil {
				return err
			}
			if err := guardConns(st, []*store.Conn{t.conn}, driver.Verdict{Risk: driver.RiskRead}); err != nil {
				return err
			}
			kargs := []string{"port-forward", "--address", "127.0.0.1", args[1], local + ":" + remote}
			if ns := firstNonEmpty(ns, t.conn.Options["namespace"]); ns != "" {
				kargs = append(kargs, "-n", ns)
			}
			if g.dryRun {
				out.P.Print("cluster.forward", map[string]any{"conn": t.conn.Name, "would_run": "kubectl " + strings.Join(kargs, " ")}, nil)
				return nil
			}
			if err := needKubectl(); err != nil {
				return err
			}
			ctx := cmd.Context()
			if g.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, g.timeout)
				defer cancel()
			}
			return runKubectl(ctx, st, t.conn, "cluster.forward", kargs, driver.RiskRead, true)
		},
	}
	nsFlags(c, &ns, nil, nil)
	return c
}
