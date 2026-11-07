package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// ----------------------------------------------------------- daemon-reload ---

func svcDaemonReloadCmd() *cobra.Command {
	var noSudo bool
	c := &cobra.Command{
		Use:     "daemon-reload TARGET",
		Short:   "Reload systemd's unit files (after writing a unit), and say which units still need it",
		Example: "  komando fs write web1 /etc/systemd/system/app.service --from app.service --sudo\n  komando svc daemon-reload web1\n  komando svc restart web1 app",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := noSystemd + "systemctl daemon-reload >&2; rc=$?\n" +
				// units whose files changed after the reload still say so
				"for u in $(systemctl list-units --all --no-legend --plain --type=service | awk '{print $1}'); do " +
				"[ \"$(systemctl show -p NeedDaemonReload --value -- \"$u\" 2>/dev/null)\" = yes ] && echo \"stale=$u\"; done\n" +
				"echo \"#komando:rc=$rc\"; exit 0"
			return runOps(cmd.Context(), opsSpec{name: "svc.daemon-reload", target: args[0], command: command, display: "svc daemon-reload",
				sudo: !noSudo, mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return daemonReloadResult(rr) }})
		},
	}
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "run without sudo")
	return c
}

func daemonReloadResult(rr *sshx.RunResult) (any, *out.Error) {
	m := marker(rr.Stdout)
	if m == "no-systemd" {
		return nil, errNoSystemd()
	}
	if m != "rc=0" {
		return nil, out.Errf(out.ExitRemote, "SVC_FAILED", "read stderr for systemd's reason; a unit file with a mistake is named there",
			"systemctl daemon-reload failed (%s)", strings.TrimPrefix(m, "rc="))
	}
	stale := []string{}
	for _, l := range strings.Split(rr.Stdout, "\n") {
		if u, ok := strings.CutPrefix(strings.TrimSpace(l), "stale="); ok {
			stale = append(stale, u)
		}
	}
	d := map[string]any{"reloaded": true, "still_stale": stale}
	if len(stale) > 0 {
		return opsWarnings{data: d, warnings: []string{"still need a reload: " + strings.Join(stale, ", ")}}, nil
	}
	return d, nil
}

// ------------------------------------------------------------------ reboot ---

// bootMark names one boot of a server: the kernel's boot id, and when
// PID 1 started (a container restarted by its runtime keeps the kernel's
// boot id, but gets a new PID 1).
const bootMark = "echo \"#komando:boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)/$(cut -d' ' -f22 /proc/1/stat 2>/dev/null)\""

type rebootRow struct {
	Host      string     `json:"host"`
	OK        bool       `json:"ok"`
	Rebooted  bool       `json:"rebooted"`
	BackAfter float64    `json:"back_after_s,omitempty"`
	Uptime    string     `json:"up_since,omitempty"`
	Error     *out.Error `json:"error,omitempty"`
}

type rebootData struct {
	Results []rebootRow  `json:"results"`
	Skipped []string     `json:"not_rebooted,omitempty"`
	Summary fleetSummary `json:"summary"`
}

func (d rebootData) Text() string {
	var sb strings.Builder
	for _, r := range d.Results {
		switch {
		case r.OK:
			fmt.Fprintf(&sb, "%s  rebooted, back after %.0fs (up since %s)\n", r.Host, r.BackAfter, r.Uptime)
		case r.Error != nil:
			fmt.Fprintf(&sb, "%s  FAILED: %s\n", r.Host, r.Error.Message)
		}
	}
	if len(d.Skipped) > 0 {
		fmt.Fprintf(&sb, "not rebooted (stopped after a failure): %s\n", strings.Join(d.Skipped, ", "))
	}
	return sb.String()
}

func rebootCmd() *cobra.Command {
	var wait time.Duration
	var noSudo bool
	c := &cobra.Command{
		Use:   "reboot TARGET",
		Short: "Reboot servers one at a time, wait for each to come back, and check it really restarted",
		Long: `Reboots each server in turn: komando asks it to reboot, waits until SSH
answers again, and checks that it started anew (a new boot id). The next
server is rebooted only when the one before came back; a server that does
not come back within --wait stops the rest.

A reboot is a destructive action: it needs --allow-dangerous (and --yes or
the approval for protected servers). Try --dry-run first.`,
		Example: "  komando reboot web1 --dry-run\n  komando reboot @web --allow-dangerous --wait 10m",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wait <= 0 {
				return out.Usage("--wait must be more than 0")
			}
			return reboot(cmd.Context(), args[0], wait, !noSudo)
		},
	}
	c.Flags().DurationVar(&wait, "wait", 5*time.Minute, "how long each server may take to come back")
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "run without sudo")
	return c
}

// rebootNow asks for a reboot a moment after the SSH command has ended, so
// the answer (the boot mark) gets back first.
const rebootNow = "nohup sh -c 'sleep 2; systemctl reboot || /sbin/reboot || reboot' >/dev/null 2>&1 &\n"

func reboot(ctx context.Context, target string, wait time.Duration, sudo bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	guardErr := guard(st, hosts, "systemctl reboot", true)
	if g.dryRun {
		plans := []map[string]any{}
		for _, h := range hosts {
			plans = append(plans, map[string]any{"host": h.Name, "address": h.Address, "remote_command": "systemctl reboot", "sudo": sudo, "wait": wait.String()})
		}
		res := map[string]any{"would_run": plans, "order": "one server at a time"}
		if guardErr != nil {
			res["would_be_blocked"] = toErr(guardErr)
		}
		out.P.Print("reboot", res, nil)
		return nil
	}
	if guardErr != nil {
		audit(st, "reboot", hostNames(hosts), "systemctl reboot", false, map[string]any{"blocked": toErr(guardErr).Code})
		return guardErr
	}
	data := rebootData{Results: []rebootRow{}}
	var fails []hostFail
	worst := 0
	for i, h := range hosts {
		r := rebootOne(ctx, st, h, wait, sudo)
		data.Results = append(data.Results, r)
		audit(st, "reboot", []string{h.Name}, "systemctl reboot", r.OK, nil)
		if r.OK {
			data.Summary.OK++
			continue
		}
		data.Summary.Failed++
		data.Summary.FailedHosts = append(data.Summary.FailedHosts, h.Name)
		worst = worse(worst, r.Error.Exit)
		fails = append(fails, hostFail{host: h.Name, reason: failReason(0, r.Error), err: r.Error})
		for _, rest := range hosts[i+1:] {
			data.Skipped = append(data.Skipped, rest.Name)
		}
		break
	}
	data.Summary.Total = len(hosts)
	return finishFleet("reboot", data, runSummary{fleetSummary: data.Summary, Skipped: len(data.Skipped), SkippedHosts: data.Skipped}, worst, fails)
}

func rebootOne(ctx context.Context, st *store.State, h *store.Host, wait time.Duration, sudo bool) rebootRow {
	r := rebootRow{Host: h.Name}
	fail := func(e *out.Error) rebootRow { r.Error = e; return r }
	var before string
	err := withClient(ctx, st, h, func(c *sshx.Client) error {
		rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: bootMark + "\n" + rebootNow, Sudo: sudo, Timeout: 30 * time.Second})
		if err != nil {
			return err
		}
		if rr.ExitCode != 0 {
			return out.Errf(out.ExitRemote, "REBOOT_FAILED", "read stderr; without sudo rights a reboot is refused",
				"the reboot command failed (exit %d): %s", rr.ExitCode, strings.TrimSpace(rr.Stderr))
		}
		before = marker(rr.Stdout)
		return nil
	})
	if err != nil {
		return fail(toErr(err))
	}
	start := time.Now()
	deadline := start.Add(wait)
	time.Sleep(5 * time.Second) // let it go down
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return fail(toErr(ctx.Err()))
		}
		var mark, since string
		err := withClient(ctx, st, h, func(c *sshx.Client) error {
			rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: bootMark + "; uptime -s 2>/dev/null", Timeout: 20 * time.Second})
			if err != nil {
				return err
			}
			mark = marker(rr.Stdout)
			for _, l := range strings.Split(rr.Stdout, "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#komando:") {
					since = l
				}
			}
			return nil
		})
		if err == nil && mark != "" && mark != before {
			r.OK, r.Rebooted, r.Uptime = true, true, since
			r.BackAfter = time.Since(start).Round(time.Second).Seconds()
			return r
		}
		time.Sleep(5 * time.Second)
	}
	return fail(out.Errf(out.ExitTimeout, "REBOOT_TIMEOUT", "check the server's console; komando did not reboot the servers after it",
		"%s did not come back within %s", h.Name, wait))
}
