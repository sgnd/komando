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
			if err := guard(st, hosts, command, !readOnly); err != nil {
				return err
			}
			env, err := parseKV(envs)
			if err != nil {
				return err
			}
			if g.dryRun {
				out.P.Print("job.start", map[string]any{"hosts": hostNames(hosts), "command": command}, nil)
				return nil
			}
			type started struct {
				ID    string     `json:"id,omitempty"`
				Host  string     `json:"host"`
				PID   int        `json:"pid,omitempty"`
				OK    bool       `json:"ok"`
				Error *out.Error `json:"error,omitempty"`
			}
			res := fanout(cmd.Context(), st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
				id := newID("j")
				inner, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: command, Env: env, Dir: dir})
				if err != nil {
					return nil, err
				}
				if sudo {
					if c.Host.SudoRef != "" {
						return nil, out.Usage("jobs cannot feed a sudo password; use passwordless sudo or `komando exec --sudo`")
					}
					inner = "sudo -n sh -c " + sshx.Q(inner)
				}
				wrapper := "( " + inner + " ); echo $? > \"$d/exit\""
				script := `d="` + jobDir(id) + `"; mkdir -p "$d" && printf '%s\n' ` + sshx.Q(command) + ` > "$d/cmd" && date -u +%s > "$d/started"; ` +
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
			data := struct {
				Jobs    []started    `json:"jobs"`
				Summary fleetSummary `json:"summary"`
				Next    string       `json:"next"`
			}{Next: "komando job status <id>  |  komando job logs <id> --offset <next_offset>  |  komando job wait <id>"}
			worst := 0
			for _, o := range res {
				if o.Err != nil {
					e := toErr(o.Err)
					worst = worse(worst, e.Exit)
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
			return finish("job.start", data, data.Summary, worst)
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
	State      string `json:"state"` // running | exited | lost
	ExitCode   *int   `json:"exit_code,omitempty"`
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

func fetchStatus(ctx context.Context, c *sshx.Client, j *store.Job, tail int) (*jobStatus, error) {
	script := `d="` + jobDir(j.ID) + `"; [ -d "$d" ] || { echo LOST; exit 0; }; ` +
		`if [ -f "$d/exit" ]; then echo "EXIT $(cat "$d/exit")"; elif kill -0 ` + strconv.Itoa(j.PID) + ` 2>/dev/null; then echo RUNNING; else echo LOST; fi; ` +
		`wc -c < "$d/out.log" 2>/dev/null || echo 0; cat "$d/started" 2>/dev/null || echo 0; date -u +%s`
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
	c.Flags().Int64Var(&limit, "limit", 256<<10, "max bytes to return")
	c.Flags().IntVar(&tail, "tail", 0, "return only the last N lines instead")
	return c
}

func jobWaitCmd() *cobra.Command {
	var interval time.Duration
	var waitTimeout time.Duration
	var tail int
	c := &cobra.Command{
		Use:   "wait JOB_ID",
		Short: "Block until the job exits (or --wait-timeout); exit code mirrors the job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			var s *jobStatus
			deadline := time.Now().Add(waitTimeout)
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				for {
					s, err = fetchStatus(cmd.Context(), c, j, tail)
					if err != nil {
						return err
					}
					if s.State != "running" {
						return nil
					}
					if time.Now().After(deadline) {
						return nil
					}
					select {
					case <-cmd.Context().Done():
						return cmd.Context().Err()
					case <-time.After(interval):
					}
				}
			})
			if err != nil {
				return err
			}
			switch {
			case s.State == "running":
				out.P.Print("job.wait", s, out.Errf(out.ExitTimeout, "WAIT_TIMEOUT", "job is still running; call wait again or read logs", "job %s still running after %s", j.ID, waitTimeout))
				return exitCode(out.ExitTimeout)
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
	c.Flags().DurationVar(&waitTimeout, "wait-timeout", 10*time.Minute, "give up waiting after this long (job keeps running)")
	c.Flags().IntVar(&tail, "tail", 30, "include last N log lines")
	return c
}

func jobKillCmd() *cobra.Command {
	var sig string
	c := &cobra.Command{
		Use:   "kill JOB_ID",
		Short: "Signal a job's process group (default TERM)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, j, h, err := lookupJob(args[0])
			if err != nil {
				return err
			}
			if err := guard(st, []*store.Host{h}, "", true); err != nil {
				return err
			}
			p := strconv.Itoa(j.PID)
			script := "kill -" + sshx.Q(strings.TrimPrefix(strings.ToUpper(sig), "SIG")) + " -- -" + p + " 2>/dev/null || kill -" + sshx.Q(strings.TrimPrefix(strings.ToUpper(sig), "SIG")) + " " + p
			var r *sshx.RunResult
			err = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
				r, err = sshx.Run(cmd.Context(), c, sshx.RunRequest{Command: script, Timeout: 30 * time.Second, MaxOutput: 4096})
				return err
			})
			if err != nil {
				return err
			}
			audit(st, "job.kill", []string{h.Name}, script, r.ExitCode == 0, map[string]any{"job": j.ID})
			if r.ExitCode != 0 {
				return out.Errf(out.ExitRemote, "KILL_FAILED", "the job may have already exited; check `komando job status`", "%s", strings.TrimSpace(r.Stderr))
			}
			out.P.Print("job.kill", map[string]any{"id": j.ID, "signal": sig, "pid": j.PID}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&sig, "signal", "TERM", "signal name (TERM, KILL, INT, HUP)")
	return c
}

func jobListCmd() *cobra.Command {
	var host string
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
			var jobs []*store.Job
			for _, j := range st.Jobs {
				if host == "" || j.Host == host {
					jobs = append(jobs, j)
				}
			}
			sort.Slice(jobs, func(a, b int) bool { return jobs[a].StartedAt.After(jobs[b].StartedAt) })
			if !refresh {
				out.P.Print("job.list", map[string]any{"count": len(jobs), "jobs": jobs}, nil)
				return nil
			}
			var rows []any
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
			out.P.Print("job.list", map[string]any{"count": len(rows), "jobs": rows}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&host, "host", "", "filter by host")
	c.Flags().BoolVar(&refresh, "refresh", false, "query each host for live state")
	return c
}

func jobRmCmd() *cobra.Command {
	var keepRemote bool
	c := &cobra.Command{
		Use:   "rm JOB_ID...",
		Short: "Forget jobs and delete their remote log directories",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			removed := []string{}
			for _, id := range args {
				st, j, h, err := lookupJob(id)
				if err != nil {
					return err
				}
				if !keepRemote {
					_ = withClient(cmd.Context(), st, h, func(c *sshx.Client) error {
						_, _, err := sshx.Output(cmd.Context(), c, `rm -rf "`+jobDir(j.ID)+`"`, 30*time.Second)
						return err
					})
				}
				if err := store.Update(func(s *store.State) error { delete(s.Jobs, id); return nil }); err != nil {
					return err
				}
				removed = append(removed, id)
			}
			out.P.Print("job.rm", map[string]any{"removed": removed}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&keepRemote, "keep-remote", false, "keep the remote log directory")
	return c
}
