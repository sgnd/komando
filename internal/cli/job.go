package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Jobs are detached remote processes (nohup/setsid) whose output lives in
// ~/.komando/jobs/<id>/ on the server. They survive the SSH connection, so
// agents can start long tasks (builds, backups, migrations) and poll them.

func newID(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + time.Now().UTC().Format("0102-150405") + "-" + hex.EncodeToString(b)
}

const jobRoot = "$HOME/.komando/jobs"

func jobDir(id string) string { return jobRoot + "/" + id }

func jobCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "job",
		Aliases: []string{"jobs"},
		Short:   "Detached long-running remote jobs: start, status, logs (incremental), wait, kill",
		Long: `Long tasks should not block an agent's tool call. 'job start' launches the
command detached on each host and returns job IDs immediately. Poll with
'job status' or 'job logs --offset N' (pass back next_offset to read only new
output), or block with 'job wait --timeout'.`,
	}
	c.AddCommand(jobStartCmd(), jobStatusCmd(), jobLogsCmd(), jobWaitCmd(), jobKillCmd(), jobListCmd(), jobRmCmd())
	return c
}

func jobStartCmd() *cobra.Command {
	var sudo, readOnly bool
	var envs []string
	var dir, cmdStr string
	c := &cobra.Command{
		Use:   "start TARGET [--] COMMAND...",
		Short: "Start a detached job on each matched host; returns job IDs immediately",
		Example: `  komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
  komando job start @web --sudo -- 'apt-get update && apt-get -y upgrade'`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := cmdStr
			if command == "" {
				command = strings.Join(args[1:], " ")
			}
			if strings.TrimSpace(command) == "" {
				return out.Usage("no command given")
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			hosts, err := resolveTargets(st, args[0])
			if err != nil {
				return err
			}
			if readOnly {
				if err := checkReadOnly(command); err != nil {
					return err
				}
			}
			if err := guard(st, hosts, command, !readOnly); err != nil {
				return err
			}
			env, err := parseEnv(envs)
			if err != nil {
				return err
			}
			if g.dryRun {
				out.P.Print("job.start", map[string]any{"hosts": hostNames(hosts), "command": command}, nil)
				return nil
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				id := newID("j")
				// The exports go to a private file the job reads and deletes:
				// a job runs for long, and its command line is visible to
				// every user on the server (ps), secrets included.
				exports, err := sshx.EnvExports(c, env)
				if err != nil {
					return nil, err
				}
				inner, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: command, Dir: dir, NoEnv: true})
				if err != nil {
					return nil, err
				}
				if exports != "" {
					inner = `. "$1"; rm -f "$1"; ` + inner
				}
				if sudo {
					if c.Host.SudoRef != "" {
						return nil, out.Usage("jobs cannot feed a sudo password; use passwordless sudo or `komando exec --sudo`")
					}
					inner = "sudo -n sh -c " + sshx.Q(inner) + ` sh "$d/env"`
				} else {
					inner = "sh -c " + sshx.Q(inner) + ` sh "$d/env"`
				}
				wrapper := "( " + inner + " ); echo $? > \"$d/exit\""
				envFile := ""
				if exports != "" {
					envFile = `(umask 077; printf '%s' ` + sshx.Q(exports) + ` > "$d/env") && `
				}
				script := `d="` + jobDir(id) + `"; mkdir -p "$d" && ` + envFile + `printf '%s\n' ` + sshx.Q(command) + ` > "$d/cmd" && date -u +%s > "$d/started"; ` +
					`export d; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + sshx.Q(wrapper) + ` > "$d/out.log" 2>&1 < /dev/null & ` +
					`else nohup sh -c ` + sshx.Q(wrapper) + ` > "$d/out.log" 2>&1 < /dev/null & fi; echo $! > "$d/pid"; echo $!`
				o, code, err := sshx.Output(ctx, c, script, 30*time.Second)
				if err != nil {
					return nil, err
				}
				pid, perr := strconv.Atoi(strings.TrimSpace(o))
				if code != 0 || perr != nil {
					return nil, out.Errf(out.ExitRemote, "JOB_START_FAILED", "", "could not start job: %s", o)
				}
				j := &store.Job{ID: id, Host: c.Host.Name, Command: command, PID: pid, RemoteDir: jobDir(id), StartedAt: time.Now().UTC()}
				if err := store.Update(func(s *store.State) error { s.Jobs[id] = j; return nil }); err != nil {
					return nil, err
				}
				return started{ID: id, Host: c.Host.Name, PID: pid, OK: true}, nil
			})
			data := jobStarted{Next: "komando job status <id>  |  komando job logs <id> --offset <next_offset>  |  komando job wait <id>"}
			worst := 0
			var fails []hostFail
			for _, o := range res {
				if o.Err != nil {
					e := toErr(o.Err)
					worst = worse(worst, e.Exit)
					fails = append(fails, hostFail{host: o.Host.Name, reason: failReason(0, e), err: e})
					data.Jobs = append(data.Jobs, started{Host: o.Host.Name, Error: e})
					data.Summary.Failed++
					data.Summary.FailedHosts = append(data.Summary.FailedHosts, o.Host.Name)
					continue
				}
				data.Jobs = append(data.Jobs, o.Value.(started))
				data.Summary.OK++
			}
			data.Summary.Total = len(res)
			audit(st, "job.start", hostNames(hosts), command, data.Summary.Failed == 0, nil)
			return finishFleet("job.start", data, runSummary{fleetSummary: data.Summary}, worst, fails)
		},
	}
	c.Flags().StringVarP(&cmdStr, "cmd", "c", "", "command string")
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "run via passwordless sudo")
	c.Flags().StringSliceVarP(&envs, "env", "e", nil, "export KEY=VALUE")
	c.Flags().StringVarP(&dir, "dir", "C", "", "remote working directory")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare read-only (skip protected-host confirmation)")
	return c
}

type jobStatus struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	Command    string `json:"command"`
	PID        int    `json:"pid"`
	State      string `json:"state"` // running | exited | killed | lost
	ExitCode   *int   `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"` // killed: the signal job kill sent
	LogBytes   int64  `json:"log_bytes"`
	StartedAt  string `json:"started_at"`
	RuntimeSec int64  `json:"runtime_sec"`
	Tail       string `json:"tail,omitempty"`
}

func lookupJob(id string) (*store.State, *store.Job, *store.Host, error) {
	st, err := loadState()
	if err != nil {
		return nil, nil, nil, err
	}
	j, ok := st.Jobs[id]
	if !ok {
		return nil, nil, nil, out.NotFound("job", id)
	}
	h, ok := st.Hosts[j.Host]
	if !ok {
		var err error
		if h, err = sshx.ParseAdhoc(j.Host); err != nil {
			return nil, nil, nil, out.NotFound("host", j.Host)
		}
	}
	return st, j, h, nil
}

// jobAlive is a shell test for a live process. kill -0 fails on another
// user's process (a --sudo job), so /proc is asked too.
func jobAlive(pid int) string {
	p := strconv.Itoa(pid)
	return `{ kill -0 ` + p + ` 2>/dev/null || [ -d /proc/` + p + ` ]; }`
}

func fetchStatus(ctx context.Context, c *sshx.Client, j *store.Job, tail int) (*jobStatus, error) {
	// the end time is when the exit (or killed) file was written, so the
	// runtime of a finished job stays put
	script := `d="` + jobDir(j.ID) + `"; [ -d "$d" ] || { echo LOST; exit 0; }; end=$(date -u +%s); ` +
		`if [ -f "$d/exit" ]; then echo "EXIT $(cat "$d/exit")"; end=$(date -u -r "$d/exit" +%s 2>/dev/null || echo $end); ` +
		`elif ` + jobAlive(j.PID) + `; then echo RUNNING; ` +
		`elif [ -f "$d/killed" ]; then echo "KILLED $(cat "$d/killed")"; end=$(date -u -r "$d/killed" +%s 2>/dev/null || echo $end); ` +
		`else echo LOST; fi; ` +
		`wc -c < "$d/out.log" 2>/dev/null || echo 0; cat "$d/started" 2>/dev/null || echo 0; echo $end`
	if tail > 0 {
		script += `; echo ---TAIL---; tail -n ` + strconv.Itoa(tail) + ` "$d/out.log" 2>/dev/null`
	}
	o, _, err := sshx.Output(ctx, c, script, 30*time.Second)
	if err != nil {
		return nil, err
	}
	head, tailOut, _ := strings.Cut(o, "---TAIL---\n")
	lines := strings.Split(strings.TrimSpace(head), "\n")
	s := &jobStatus{ID: j.ID, Host: j.Host, Command: j.Command, PID: j.PID, StartedAt: j.StartedAt.Format(time.RFC3339), Tail: tailOut}
	if len(lines) > 0 {
		switch {
		case lines[0] == "RUNNING":
			s.State = "running"
		case strings.HasPrefix(lines[0], "EXIT "):
			s.State = "exited"
			if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lines[0], "EXIT "))); err == nil {
				s.ExitCode = &n
			}
		case strings.HasPrefix(lines[0], "KILLED"):
			s.State = "killed"
			s.Signal = strings.TrimSpace(strings.TrimPrefix(lines[0], "KILLED"))
		default:
			s.State = "lost"
		}
	}
	if len(lines) >= 4 {
		s.LogBytes, _ = strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
		startU, _ := strconv.ParseInt(strings.TrimSpace(lines[2]), 10, 64)
		nowU, _ := strconv.ParseInt(strings.TrimSpace(lines[3]), 10, 64)
		if startU > 0 {
			s.RuntimeSec = nowU - startU
		}
	}
	return s, nil
}

func jobStatusCmd() *cobra.Command {
	var tail int
	c := &cobra.Command{
		Use:   "status JOB_ID",
		Short: "Show job state (running|exited|lost), exit code, runtime and log tail",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			var s *jobStatus
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				s, err = fetchStatus(cmd.Context(), c, j, tail)
				return err
			})
			if err != nil {
				return err
			}
			out.P.Print("job.status", s, nil)
			return nil
		},
	}
	c.Flags().IntVar(&tail, "tail", 20, "include last N log lines (0 = none)")
	return c
}

type jobLogs struct {
	ID         string `json:"id"`
	Offset     int64  `json:"offset"`
	NextOffset int64  `json:"next_offset"`
	Content    string `json:"content"`
	State      string `json:"state"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	More       bool   `json:"more"`
}

func (l jobLogs) Text() string { return l.Content }

func jobLogsCmd() *cobra.Command {
	var offset int64
	var limit int64
	var tail int
	c := &cobra.Command{
		Use:   "logs JOB_ID",
		Short: "Read job output incrementally (--offset from previous next_offset) or --tail N lines",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if offset < 0 {
				return out.Usage("--offset must be 0 or more (it is a byte position; use --tail N for the last lines)")
			}
			if limit <= 0 {
				return out.Usage("--max-bytes must be more than 0")
			}
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			var res jobLogs
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				s, err := fetchStatus(cmd.Context(), c, j, 0)
				if err != nil {
					return err
				}
				log := jobDir(j.ID) + "/out.log"
				var script string
				if tail > 0 {
					script = `tail -n ` + strconv.Itoa(tail) + ` "` + log + `"`
					offset = max(0, s.LogBytes)
				} else {
					script = `tail -c +` + strconv.FormatInt(offset+1, 10) + ` "` + log + `" 2>/dev/null | head -c ` + strconv.FormatInt(limit, 10)
				}
				r, err := sshx.Run(cmd.Context(), c, sshx.RunRequest{Command: script, MaxOutput: int(limit) + 1, Timeout: time.Minute})
				if err != nil {
					return err
				}
				res = jobLogs{ID: j.ID, Offset: offset, Content: r.Stdout, State: s.State, ExitCode: s.ExitCode}
				if tail > 0 {
					res.NextOffset = s.LogBytes
				} else {
					res.NextOffset = offset + int64(len(r.Stdout))
					res.More = res.NextOffset < s.LogBytes
				}
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("job.logs", res, nil)
			return nil
		},
	}
	c.Flags().Int64Var(&offset, "offset", 0, "byte offset to read from (use next_offset from the previous call)")
	c.Flags().Int64Var(&limit, "max-bytes", 256<<10, "max bytes to return")
	aliasFlag(c.Flags(), "limit", "max-bytes")
	c.Flags().IntVar(&tail, "tail", 0, "return only the last N lines instead")
	return c
}

func jobWaitCmd() *cobra.Command {
	var interval time.Duration
	var waitTimeout time.Duration
	var tail int
	c := &cobra.Command{
		Use:   "wait JOB_ID",
		Short: "Block until the job exits (or --timeout); exit code mirrors the job",
		Long: `Waits until the job ends, polling every --interval. --timeout (default 10m)
is how long to wait; the job keeps running after it (exit 7, WAIT_TIMEOUT).`,
		Example: "  komando job wait j1103-101500-ab12cd34 --timeout 30m",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("wait-timeout") && g.timeout > 0 {
				waitTimeout = g.timeout // --timeout is the wait limit here
			}
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			var s *jobStatus
			deadline := time.Now().Add(waitTimeout)
			pause := func() error {
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(interval):
					return nil
				}
			}
			// a long wait outlives SSH connections (a NAT or firewall drops an
			// idle one after some minutes): connect again and keep waiting,
			// like kubectl wait, until the job ends or the deadline passes
			for {
				var done bool
				err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
					for {
						var ferr error
						if s, ferr = fetchStatus(cmd.Context(), c, j, tail); ferr != nil {
							return ferr
						}
						if s.State != "running" || time.Now().After(deadline) {
							done = true
							return nil
						}
						if err := pause(); err != nil {
							return err
						}
					}
				})
				if done || cmd.Context().Err() != nil || time.Now().After(deadline) || !transient(err) {
					break
				}
				if err := pause(); err != nil {
					return err
				}
			}
			if err != nil && (s == nil || !time.Now().After(deadline)) {
				return err
			}
			switch {
			case s.State == "running":
				out.P.Print("job.wait", s, out.Errf(out.ExitTimeout, "WAIT_TIMEOUT", "job is still running; call wait again or read logs", "job %s still running after %s", j.ID, waitTimeout))
				return exitCode(out.ExitTimeout)
			case s.State == "killed":
				out.P.Print("job.wait", s, out.Errf(out.ExitRemote, "JOB_KILLED", "it was stopped with `komando job kill`", "job %s was killed (%s)", j.ID, s.Signal))
				return exitCode(out.ExitRemote)
			case s.State == "lost":
				out.P.Print("job.wait", s, out.Errf(out.ExitRemote, "JOB_LOST", "process died without recording an exit code (killed or server rebooted)", "job %s lost", j.ID))
				return exitCode(out.ExitRemote)
			case s.ExitCode != nil && *s.ExitCode != 0:
				out.P.Print("job.wait", s, out.Errf(out.ExitRemote, "JOB_FAILED", "", "job exited with %d", *s.ExitCode))
				return exitCode(out.ExitRemote)
			}
			out.P.Print("job.wait", s, nil)
			return nil
		},
	}
	c.Flags().DurationVar(&interval, "interval", 3*time.Second, "poll interval")
	c.Flags().DurationVar(&waitTimeout, "wait-timeout", 10*time.Minute, "same as --timeout: give up waiting after this long (job keeps running)")
	_ = c.Flags().MarkHidden("wait-timeout")
	c.Flags().IntVar(&tail, "tail", 30, "include last N log lines")
	return c
}

func jobKillCmd() *cobra.Command {
	var sig string
	var sudo bool
	c := &cobra.Command{
		Use:   "kill JOB_ID",
		Short: "Signal a job's process group (default TERM); a job that already ended is left as it is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sig = strings.TrimPrefix(strings.ToUpper(sig), "SIG")
			if !validSignal(sig) {
				return out.Usage("unknown --signal %q (use TERM, KILL, INT, HUP, QUIT, USR1, USR2 or a number)", sig)
			}
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, "", true); err != nil {
				return err
			}
			script := jobKillScript(j, sig)
			if g.dryRun {
				out.P.Print("job.kill", map[string]any{"job": j.ID, "host": h.Name, "would_run": script}, nil)
				return nil
			}
			var r *sshx.RunResult
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				r, err = sshx.Run(cmd.Context(), c, sshx.RunRequest{Command: script, Sudo: sudo, Timeout: 30 * time.Second, MaxOutput: 4096})
				return err
			})
			if err != nil {
				return err
			}
			audit(st, "job.kill", []string{h.Name}, script, r.ExitCode == 0, map[string]any{"job": j.ID})
			if r.ExitCode != 0 {
				hint := "check `komando job status " + j.ID + "`"
				if strings.Contains(r.Stderr, "not permitted") && !sudo {
					hint = "the job runs as another user (started with --sudo?); add --sudo"
				}
				return out.Errf(out.ExitRemote, "KILL_FAILED", hint, "%s", strings.TrimSpace(r.Stderr))
			}
			res := jobKilled{ID: j.ID, Signal: sig, PID: j.PID, State: "killed"}
			switch strings.TrimSpace(r.Stdout) {
			case "EXITED":
				res.State, res.Note = "exited", "the job had already ended; nothing to do"
			case "KILLED":
				res.Note = "the job was already killed; nothing to do"
			case "GONE":
				res.State, res.Note = "gone", "the process was no longer running; nothing to do"
			}
			out.P.Print("job.kill", res, nil)
			return nil
		},
	}
	c.Flags().StringVar(&sig, "signal", "TERM", "signal name (TERM, KILL, INT, HUP)")
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "signal via sudo (for jobs started with --sudo)")
	return c
}

// jobKillScript signals the job's process group and records the kill in
// the job folder, so status says "killed" instead of "lost". A job that
// already ended is left alone.
func jobKillScript(j *store.Job, sig string) string {
	p := strconv.Itoa(j.PID)
	return `d="` + jobDir(j.ID) + `"; if [ -f "$d/exit" ]; then echo EXITED; exit 0; fi; ` +
		`if ! ` + jobAlive(j.PID) + `; then if [ -f "$d/killed" ]; then echo KILLED; else echo GONE; fi; exit 0; fi; ` +
		`printf '%s\n' ` + sshx.Q(sig) + ` > "$d/killed" 2>/dev/null; ` +
		`kill -` + sig + ` -- -` + p + ` 2>/dev/null || kill -` + sig + ` ` + p
}

func validSignal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

type jobKilled struct {
	ID     string `json:"id"`
	Signal string `json:"signal"`
	PID    int    `json:"pid"`
	State  string `json:"state"` // killed | exited | gone
	Note   string `json:"note,omitempty"`
}

func (k jobKilled) Text() string {
	if k.Note != "" {
		return k.ID + ": " + k.Note
	}
	return "sent " + k.Signal + " to job " + k.ID + " (pid " + strconv.Itoa(k.PID) + ")"
}

func jobListCmd() *cobra.Command {
	var target string
	var refresh bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List known jobs (--refresh queries live state)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			var names map[string]bool
			if target != "" {
				names = targetNames(st, target)
			}
			jobs := []*store.Job{}
			for _, j := range st.Jobs {
				if target == "" || names[j.Host] {
					jobs = append(jobs, j)
				}
			}
			sort.Slice(jobs, func(a, b int) bool { return jobs[a].StartedAt.After(jobs[b].StartedAt) })
			if !refresh {
				out.P.Print("job.list", jobList{Count: len(jobs), Jobs: jobs}, nil)
				return nil
			}
			rows := []any{}
			for _, j := range jobs {
				h, ok := st.Hosts[j.Host]
				if !ok {
					rows = append(rows, map[string]any{"id": j.ID, "host": j.Host, "state": "unknown-host"})
					continue
				}
				var s *jobStatus
				err := withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
					var e error
					s, e = fetchStatus(cmd.Context(), c, j, 0)
					return e
				})
				if err != nil {
					rows = append(rows, map[string]any{"id": j.ID, "host": j.Host, "state": "unreachable", "error": toErr(err)})
					continue
				}
				rows = append(rows, s)
			}
			out.P.Print("job.list", jobList{Count: len(rows), Jobs: rows}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "only jobs on these servers (a selector, e.g. @web)")
	aliasFlag(c.Flags(), "host", "target")
	c.Flags().BoolVar(&refresh, "refresh", false, "query each host for live state")
	return c
}

func jobRmCmd() *cobra.Command {
	var keepRemote, force bool
	c := &cobra.Command{
		Use:   "rm JOB_ID...",
		Short: "Forget jobs and delete their remote log directories (a running job needs `job kill` or --kill)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			removed := []string{}
			for _, id := range args {
				st, j, h, err := lookupJob(id)
				if err != nil {
					return err
				}
				err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
					s, err := fetchStatus(cmd.Context(), c, j, 0)
					if err != nil {
						return err
					}
					if s.State == "running" {
						if !force {
							return out.Errf(out.ExitConflict, "JOB_RUNNING", "stop it first with `komando job kill "+id+"`, or pass --kill to stop and remove it",
								"job %s is still running", id)
						}
						if !g.dryRun {
							if _, _, err := sshx.Output(cmd.Context(), c, jobKillScript(j, "TERM"), 30*time.Second); err != nil {
								return err
							}
						}
					}
					if !keepRemote && !g.dryRun {
						_, _, err := sshx.Output(cmd.Context(), c, `rm -rf "`+jobDir(j.ID)+`"`, 30*time.Second)
						return err
					}
					return nil
				})
				if err != nil && toErr(err).Code == "JOB_RUNNING" {
					return err
				}
				// an unreachable server: the record goes anyway (its logs stay there)
				if err := store.Update(func(s *store.State) error { delete(s.Jobs, id); return nil }); err != nil {
					return err
				}
				removed = append(removed, id)
			}
			if g.dryRun {
				out.P.Print("job.rm", map[string]any{"would_remove": removed}, nil)
				return nil
			}
			out.P.Print("job.rm", map[string]any{"removed": removed}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&keepRemote, "keep-remote", false, "keep the remote log directory")
	c.Flags().BoolVar(&force, "kill", false, "kill a running job first, then remove it")
	return c
}

// --- text output -------------------------------------------------------------

type started struct {
	ID    string     `json:"id,omitempty"`
	Host  string     `json:"host"`
	PID   int        `json:"pid,omitempty"`
	OK    bool       `json:"ok"`
	Error *out.Error `json:"error,omitempty"`
}

type jobStarted struct {
	Jobs    []started    `json:"jobs"`
	Summary fleetSummary `json:"summary"`
	Next    string       `json:"next"`
}

func (d jobStarted) Text() string {
	rows := [][]string{}
	for _, j := range d.Jobs {
		if j.Error != nil {
			rows = append(rows, []string{"-", j.Host, "-", "failed: " + j.Error.Message})
			continue
		}
		rows = append(rows, []string{j.ID, j.Host, strconv.Itoa(j.PID), "started"})
	}
	s := textTable([]string{"id", "host", "pid", "state"}, rows)
	if d.Summary.OK > 0 {
		id := "<id>"
		if d.Summary.OK == 1 {
			for _, j := range d.Jobs {
				if j.ID != "" {
					id = j.ID
				}
			}
		}
		s += "\nfollow it with: komando job logs " + id + " --tail 20   |   komando job wait " + id + "\n"
	}
	return s
}

func (s *jobStatus) describe() string {
	switch s.State {
	case "exited":
		code := "?"
		if s.ExitCode != nil {
			code = strconv.Itoa(*s.ExitCode)
		}
		return "exited " + code + " after " + humanAge(time.Duration(s.RuntimeSec)*time.Second)
	case "running":
		return "running for " + humanAge(time.Duration(s.RuntimeSec)*time.Second)
	case "killed":
		return "killed (" + s.Signal + ") after " + humanAge(time.Duration(s.RuntimeSec)*time.Second)
	}
	return "lost: the process ended without an exit code (server rebooted, or killed outside komando)"
}

func (s *jobStatus) Text() string {
	var b strings.Builder
	b.WriteString("job " + s.ID + " on " + s.Host + ": " + s.describe() + "\n")
	b.WriteString("command: " + s.Command + "\n")
	b.WriteString("pid " + strconv.Itoa(s.PID) + ", started " + s.StartedAt + ", log " + humanBytes(s.LogBytes) + "\n")
	if t := strings.TrimRight(s.Tail, "\n"); t != "" {
		b.WriteString("--- last lines ---\n" + t + "\n")
	}
	return b.String()
}

type jobList struct {
	Count int `json:"count"`
	Jobs  any `json:"jobs"`
}

func (l jobList) Text() string {
	rows := [][]string{}
	add := func(id, host, state, exit string, started time.Time, command string) {
		age := "-"
		if !started.IsZero() {
			age = humanAge(time.Since(started))
		}
		if len(command) > 60 {
			command = command[:57] + "..."
		}
		rows = append(rows, []string{id, host, state, exit, age, command})
	}
	switch js := l.Jobs.(type) {
	case []*store.Job:
		for _, j := range js {
			add(j.ID, j.Host, "?", "", j.StartedAt, j.Command)
		}
	case []any:
		for _, r := range js {
			switch v := r.(type) {
			case *jobStatus:
				exit := ""
				if v.ExitCode != nil {
					exit = strconv.Itoa(*v.ExitCode)
				}
				t, _ := time.Parse(time.RFC3339, v.StartedAt)
				add(v.ID, v.Host, v.State, exit, t, v.Command)
			case map[string]any:
				add(v["id"].(string), v["host"].(string), v["state"].(string), "", time.Time{}, "")
			}
		}
	}
	if len(rows) == 0 {
		return "no jobs\n"
	}
	s := textTable([]string{"id", "host", "state", "exit", "age", "command"}, rows)
	if _, ok := l.Jobs.([]*store.Job); ok {
		s += "(state: add --refresh to ask the servers)\n"
	}
	return s
}

// transient: the connection broke (dropped, reset, timed out), so trying
// again may work. A refused login or a changed host key is not transient.
func transient(err error) bool {
	if err == nil {
		return false
	}
	if e := toErr(err); e.Exit == out.ExitConnect || e.Exit == out.ExitTimeout {
		return e.Code != "AUTH_FAILED" && !strings.HasPrefix(e.Code, "HOSTKEY")
	}
	m := strings.ToLower(err.Error())
	for _, s := range []string{"eof", "connection reset", "broken pipe", "closed network connection", "i/o timeout", "connection lost"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
