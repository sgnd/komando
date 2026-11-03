package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func readAllStdin() ([]byte, error) { return io.ReadAll(os.Stdin) }

type execHostResult struct {
	Host string `json:"host"`
	OK   bool   `json:"ok"`
	*sshx.RunResult
	Error *out.Error `json:"error,omitempty"`
}

type execData struct {
	Command string           `json:"command"`
	Results []execHostResult `json:"results"`
	Summary runSummary       `json:"summary"`
	// streamed: the output was printed live (--stream, follow), so the
	// final text does not repeat it
	streamed bool
}

// Text is the output the way ssh shows it: one server prints its stdout
// and stderr as they are; several get a "=== host [status]" block each,
// with their stderr inside, marked [stderr].
func (d execData) Text() string {
	var sb strings.Builder
	multi := len(d.Results) > 1
	for _, r := range d.Results {
		if multi {
			fmt.Fprintf(&sb, "=== %s [%s]\n", r.Host, hostStatus(r))
		}
		if r.RunResult != nil && !d.streamed {
			sb.WriteString(r.Stdout)
			if r.Stdout != "" && !strings.HasSuffix(r.Stdout, "\n") && multi {
				sb.WriteString("\n")
			}
			if r.Stderr != "" {
				if multi {
					for _, line := range strings.SplitAfter(strings.TrimRight(r.Stderr, "\n"), "\n") {
						sb.WriteString("[stderr] " + strings.TrimRight(line, "\n") + "\n")
					}
				} else if r.Error == nil || r.Error.Message != strings.TrimSpace(r.Stderr) { // else the closing line says it
					fmt.Fprint(os.Stderr, out.SafeText(out.P.Redact(r.Stderr)))
				}
			}
		}
		if r.Error != nil && multi && r.Error.Code != "SKIPPED" {
			fmt.Fprintf(&sb, "error [%s]: %s\n", r.Error.Code, r.Error.Message)
			if r.Error.Hint != "" {
				fmt.Fprintf(&sb, "hint: %s\n", r.Error.Hint)
			}
		}
	}
	return sb.String()
}

func hostStatus(r execHostResult) string {
	switch {
	case r.Error != nil && r.Error.Code == "SKIPPED":
		return "skipped"
	case r.OK && r.RunResult != nil:
		return fmt.Sprintf("ok exit=%d", r.ExitCode)
	case r.OK:
		return "ok"
	case r.RunResult != nil && r.TimedOut:
		return "FAILED timed out"
	case r.RunResult != nil:
		return fmt.Sprintf("FAILED exit=%d", r.ExitCode)
	case r.Error != nil:
		return "FAILED " + failReason(0, r.Error)
	}
	return "FAILED"
}

type execOpts struct {
	sudo      bool
	sudoUser  string
	env       []string
	dir       string
	stdinFile string
	pty       bool
	stream    bool
	failFast  bool
	display   string // what output and the audit log show instead of a long generated script
	// follow: a log follow (logs --follow). Reaching --timeout is how it
	// ends, not a failure.
	follow bool
	// exitMap turns a remote exit code into a typed error (fs commands:
	// 83 = no such file ...); nil keeps the plain "exit N".
	exitMap func(code int, stderr string) *out.Error
}

func (o *execOpts) bind(c *cobra.Command) {
	f := c.Flags()
	f.BoolVarP(&o.sudo, "sudo", "s", false, "run via sudo (non-interactive; uses host sudo-ref if set)")
	f.StringVar(&o.sudoUser, "sudo-user", "", "run as this user via sudo -u")
	f.StringSliceVarP(&o.env, "env", "e", nil, "export KEY=VALUE before the command (repeatable)")
	f.StringVarP(&o.dir, "dir", "C", "", "remote working directory")
	f.StringVar(&o.stdinFile, "stdin-file", "", "send this local file as stdin ('-' = komando's stdin)")
	f.BoolVar(&o.pty, "pty", false, "allocate a pseudo-terminal (some tools require it)")
	f.BoolVar(&o.stream, "stream", false, "stream output as NDJSON events while running")
	f.BoolVar(&o.failFast, "fail-fast", false, "stop starting new hosts after the first failure")
}

func execCmd() *cobra.Command {
	var o execOpts
	var cmdStr string
	var readOnly bool
	c := &cobra.Command{
		Use:     "exec TARGET [--] COMMAND...",
		Aliases: []string{"run", "x"},
		Short:   "Run a shell command on one or many hosts in parallel",
		Long: `Runs COMMAND through the remote login shell on every host matched by TARGET.
Per-host stdout, stderr, exit_code and duration are returned. A non-zero exit
on any host makes komando exit 5 (connection problems exit 4).

Destructive commands (rm -rf /, mkfs, reboot, DROP DATABASE, ...) are blocked
unless --allow-dangerous is given. Hosts marked protected need --yes unless
--read-only is declared.`,
		Example: `  komando exec web1 -- uptime
  komando exec @web -P 20 -- 'df -h / | tail -1'
  komando exec tag:prod --sudo -- systemctl is-active nginx
  komando exec db1 --read-only -- 'psql -c "select 1"'
  cat deploy.sh | komando exec web1 --stdin-file - -- 'bash -s'`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := cmdStr
			if command == "" {
				command = strings.Join(args[1:], " ")
			}
			if strings.TrimSpace(command) == "" {
				return out.Usage("no command given: komando exec TARGET -- COMMAND")
			}
			var stdin []byte
			if o.stdinFile != "" {
				var err error
				if stdin, err = readFileOrStdin(o.stdinFile); err != nil {
					return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "check the --stdin-file path", "%v", err)
				}
			}
			if readOnly {
				if err := checkReadOnly(command); err != nil {
					return err
				}
			}
			return runFleet(cmd.Context(), "exec", args[0], command, stdin, o, !readOnly)
		},
	}
	o.bind(c)
	c.Flags().StringVarP(&cmdStr, "cmd", "c", "", "command string (alternative to args after --)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare the command read-only (skips protected-host confirmation)")
	return c
}

func scriptCmd() *cobra.Command {
	var o execOpts
	var interpreter string
	var readOnly bool
	var argsList []string
	c := &cobra.Command{
		Use:   "script TARGET FILE",
		Short: "Run a local script file on remote hosts (streamed via stdin, nothing left on disk)",
		Example: `  komando script @web ./deploy.sh --arg v1.2.3 --sudo
  komando script db1 ./backup.py --interpreter python3`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := readFileOrStdin(args[1])
			if err != nil {
				return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "", "%v", err)
			}
			if interpreter == "" {
				interpreter = "sh"
				if first, _, _ := strings.Cut(string(body), "\n"); strings.HasPrefix(first, "#!") {
					f := strings.Fields(strings.TrimPrefix(first, "#!"))
					if len(f) > 0 {
						interpreter = f[len(f)-1]
						if !strings.HasSuffix(f[0], "env") {
							interpreter = strings.Join(f, " ")
						}
					}
				}
			}
			command := scriptCommand(interpreter, argsList)
			if err := guardBody(string(body)); err != nil {
				return err
			}
			if readOnly {
				if err := checkReadOnly(string(body)); err != nil {
					return err
				}
			}
			return runFleet(cmd.Context(), "script", args[0], command, body, o, !readOnly)
		},
	}
	o.bind(c)
	c.Flags().StringVar(&interpreter, "interpreter", "", "remote interpreter (default: from shebang, else sh)")
	c.Flags().StringArrayVar(&argsList, "arg", nil, "argument passed to the script (repeatable)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare the script read-only")
	return c
}

// scriptCommand is how an interpreter reads a script from stdin, with
// arguments: POSIX shells take "-s -- ARGS", the others "- ARGS" (perl,
// python, ruby, node and php all read "-" as stdin).
func scriptCommand(interpreter string, args []string) string {
	base := interpreter
	if f := strings.Fields(interpreter); len(f) > 0 {
		base = path.Base(f[0])
		if base == "env" && len(f) > 1 {
			base = path.Base(f[len(f)-1])
		}
	}
	shell := false
	for _, sh := range []string{"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "busybox"} {
		if base == sh {
			shell = true
		}
	}
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = sshx.Q(a)
	}
	if shell {
		if len(q) == 0 {
			return interpreter + " -s"
		}
		return interpreter + " -s -- " + strings.Join(q, " ")
	}
	return strings.TrimSpace(interpreter + " - " + strings.Join(q, " "))
}

// guardBody applies the destructive-command policy to every line of a script.
func guardBody(body string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	return guard(st, nil, body, false)
}

// runFleet executes command on all hosts matching target and prints results.
func runFleet(ctx context.Context, name, target, command string, stdin []byte, o execOpts, mutating bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	shown := command
	if o.display != "" {
		shown = o.display
	}
	guardErr := guard(st, hosts, command, mutating)
	if guardErr != nil && !g.dryRun {
		audit(st, name, hostNames(hosts), shown, false, map[string]any{"blocked": toErr(guardErr).Code})
		return guardErr
	}
	env, err := parseEnv(o.env)
	if err != nil {
		return err
	}
	req := sshx.RunRequest{Command: command, Sudo: o.sudo || o.sudoUser != "", SudoUser: o.sudoUser, Env: env, Dir: o.dir,
		Stdin: stdin, Timeout: cmdTimeout(st), MaxOutput: maxOutput(st), PTY: o.pty}

	if g.dryRun {
		plans := []map[string]any{}
		for _, h := range hosts {
			full, _, err := sshx.BuildCommand(&sshx.Client{Host: h}, req)
			if err != nil {
				full = "<error: " + err.Error() + ">"
			}
			if o.display != "" {
				full = o.display
			}
			plans = append(plans, map[string]any{"host": h.Name, "address": h.Address, "remote_command": full, "stdin_bytes": len(stdin)})
		}
		res := map[string]any{"would_run": plans}
		if guardErr != nil {
			res["would_be_blocked"] = toErr(guardErr)
		} else if b := out.P.Blocked(); b != nil {
			res["would_be_blocked"] = b
		}
		out.P.Print(name, res, nil)
		return nil
	}

	follow := o.follow || (o.stream && name == "logs") // logs --follow
	var mu sync.Mutex
	var failed bool
	run := func(ctx context.Context, c *sshx.Client) (any, error) {
		if o.failFast {
			mu.Lock()
			f := failed
			mu.Unlock()
			if f {
				return nil, out.Errf(out.ExitError, "SKIPPED", "", "skipped due to --fail-fast")
			}
		}
		r := req
		if o.stream {
			host := c.Host.Name
			many := len(hosts) > 1
			r.Stream = func(stream string, chunk []byte) {
				mu.Lock()
				defer mu.Unlock()
				if out.P.Format == "text" { // a person: plain lines, marked by server when there are several
					w := os.Stdout
					if stream == "stderr" {
						w = os.Stderr
					}
					for _, line := range strings.SplitAfter(string(chunk), "\n") {
						if line == "" {
							continue
						}
						if many {
							line = "[" + host + "] " + line
						}
						fmt.Fprint(w, out.SafeText(out.P.Redact(line)))
					}
					return
				}
				out.P.Event(map[string]any{"event": "output", "host": host, "stream": stream, "data": string(chunk)})
			}
		}
		res, err := sshx.Run(ctx, c, r)
		if o.failFast && (err != nil || res.ExitCode != 0) {
			mu.Lock()
			failed = true
			mu.Unlock()
		}
		return res, err
	}
	var results []outcome
	if o.failFast && parallelism(st) <= 1 {
		// one at a time, in name order, and nobody is dialled after a failure
		ordered := append([]*store.Host(nil), hosts...)
		sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
		for _, h := range ordered {
			if failed {
				results = append(results, outcome{Host: h, Err: out.Errf(out.ExitError, "SKIPPED", "", "skipped due to --fail-fast")})
				continue
			}
			results = append(results, fanout(ctx, st, []*store.Host{h}, run)...)
			if r := results[len(results)-1]; r.Err != nil {
				failed = true
			}
		}
	} else {
		results = fanout(ctx, st, hosts, run)
	}

	data := execData{Command: shown, Results: make([]execHostResult, 0, len(results)), streamed: o.stream && out.P.Format == "text"}
	worst := 0
	var fails []hostFail
	for _, r := range results {
		hr := execHostResult{Host: r.Host.Name}
		if r.Err != nil {
			hr.Error = toErr(r.Err)
			if hr.Error.Code == "SKIPPED" {
				data.Summary.Skipped++
				data.Summary.SkippedHosts = append(data.Summary.SkippedHosts, hr.Host)
				data.Results = append(data.Results, hr)
				continue
			}
			worst = worse(worst, hr.Error.Exit)
			fails = append(fails, hostFail{host: hr.Host, reason: failReason(0, hr.Error), err: hr.Error})
		} else {
			hr.RunResult = r.Value.(*sshx.RunResult)
			if hr.TimedOut && follow {
				// --timeout is how a follow ends: what came so far is the result
				hr.TimedOut, hr.ExitCode = false, 0
			}
			hr.OK = hr.ExitCode == 0 && !hr.TimedOut
			switch {
			case hr.TimedOut:
				hr.Error = out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout or use `komando job start` for long tasks", "command timed out after %s", req.Timeout)
				worst = worse(worst, out.ExitTimeout)
				fails = append(fails, hostFail{host: hr.Host, reason: "timed out", err: hr.Error})
			case !hr.OK && o.exitMap != nil && o.exitMap(hr.ExitCode, hr.Stderr) != nil:
				hr.Error = o.exitMap(hr.ExitCode, hr.Stderr)
				worst = worse(worst, hr.Error.Exit)
				fails = append(fails, hostFail{host: hr.Host, reason: failReason(hr.ExitCode, hr.Error), err: hr.Error})
			case !hr.OK:
				worst = worse(worst, out.ExitRemote)
				fails = append(fails, hostFail{host: hr.Host, reason: fmt.Sprintf("exit %d", hr.ExitCode)})
			}
		}
		if hr.OK {
			data.Summary.OK++
		} else {
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, hr.Host)
		}
		data.Results = append(data.Results, hr)
	}
	data.Summary.Total = len(results)
	codes := map[string]int{}
	for _, r := range data.Results {
		if r.RunResult != nil {
			codes[r.Host] = r.ExitCode
		} else {
			codes[r.Host] = -1
		}
	}
	audit(st, name, hostNames(hosts), shown, data.Summary.Failed == 0, map[string]any{"exit_codes": codes, "sudo": req.Sudo})
	if o.stream && out.P.Format != "text" {
		out.P.Event(map[string]any{"event": "done", "summary": data.Summary})
	}
	err = finishFleet(name, data, data.Summary, worst, fails)
	truncationNotes(data.Results, req.MaxOutput, len(results) > 1)
	return err
}

// runOne is the building block for module commands (svc, docker, pkg ...):
// run a fixed command on a target, honouring policy and dry-run.
func runOne(ctx context.Context, name, target, command string, sudo, mutating bool) error {
	o := execOpts{sudo: sudo}
	return runFleet(ctx, name, target, command, nil, o, mutating)
}

// probe runs a read-only command on all target hosts and lets parse turn
// stdout into structured data.
func probe(ctx context.Context, name, target, command string, sudo bool, parse func(h *store.Host, stdout string) (any, error)) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	if g.dryRun {
		out.P.Print(name, map[string]any{"hosts": hostNames(hosts), "would_run": command}, nil)
		return nil
	}
	type row struct {
		Host     string     `json:"host"`
		OK       bool       `json:"ok"`
		Data     any        `json:"data,omitempty"`
		ExitCode *int       `json:"exit_code,omitempty"`
		Stderr   string     `json:"stderr,omitempty"`
		Error    *out.Error `json:"error,omitempty"`
	}
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		return sshx.Run(ctx, c, sshx.RunRequest{Command: command, Sudo: sudo, Timeout: cmdTimeout(st), MaxOutput: maxOutput(st)})
	})
	data := struct {
		Results []row        `json:"results"`
		Summary fleetSummary `json:"summary"`
	}{Results: []row{}}
	worst := 0
	var fails []hostFail
	for _, o := range res {
		r := row{Host: o.Host.Name}
		if o.Err != nil {
			r.Error = toErr(o.Err)
			worst = worse(worst, r.Error.Exit)
			fails = append(fails, hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error})
		} else {
			rr := o.Value.(*sshx.RunResult)
			code := rr.ExitCode
			r.ExitCode = &code
			if parse != nil {
				d, perr := parse(o.Host, rr.Stdout)
				if perr != nil {
					r.Error = toErr(perr)
				}
				r.Data = d
			} else {
				r.Data = rr.Stdout
			}
			r.OK = rr.ExitCode == 0 && r.Error == nil
			if !r.OK {
				r.Stderr = strings.TrimSpace(rr.Stderr)
				exit := out.ExitRemote
				f := hostFail{host: r.Host, reason: fmt.Sprintf("exit %d", rr.ExitCode)}
				if rr.ExitCode == 0 && r.Error != nil && r.Error.Exit != 0 {
					exit = r.Error.Exit // the parser found the problem (NXDOMAIN, closed port ...)
					f = hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error}
				}
				if rr.TimedOut {
					r.Error = out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "command timed out")
					exit = out.ExitTimeout
					f = hostFail{host: r.Host, reason: "timed out", err: r.Error}
				}
				worst = worse(worst, exit)
				fails = append(fails, f)
			}
		}
		if r.OK {
			data.Summary.OK++
		} else {
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Host)
		}
		data.Results = append(data.Results, r)
	}
	data.Summary.Total = len(res)
	audit(st, name, hostNames(hosts), command, data.Summary.Failed == 0, nil)
	return finishFleet(name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}
