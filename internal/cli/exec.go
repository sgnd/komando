package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
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
	case r.Error != nil && r.Error.Code == "CONNECTION_LOST":
		return "FAILED connection lost, outcome unknown"
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
	f.BoolVarP(&o.sudo, "sudo", "s", false, "run with sudo (never prompts; uses the server's --sudo-ref password if set)")
	f.StringVar(&o.sudoUser, "sudo-user", "", "run as this user with sudo -u")
	f.StringSliceVarP(&o.env, "env", "e", nil, "export KEY=VALUE before the command (repeatable)")
	f.StringVarP(&o.dir, "dir", "C", "", "working directory on the server")
	f.StringVar(&o.stdinFile, "stdin-file", "", "send this file on this computer as stdin ('-' = komando's stdin)")
	f.BoolVar(&o.pty, "pty", false, "allocate a pseudo-terminal (some tools need one)")
	f.BoolVar(&o.stream, "stream", false, "stream output as NDJSON events while it runs")
	f.BoolVar(&o.failFast, "fail-fast", false, "start no more servers after the first failure")
}

func execCmd() *cobra.Command {
	var o execOpts
	var cmdStr string
	var readOnly bool
	c := &cobra.Command{
		Use:     "exec TARGET [--] COMMAND...",
		Aliases: []string{"run", "x"},
		Short:   "Run a shell command on one or many servers in parallel",
		Long: `Runs COMMAND through the login shell on every server TARGET picks
(PowerShell on Windows servers). Each server's result has its stdout,
stderr, exit_code and duration. A non-zero exit on any server makes
komando exit 5 (connection problems exit 4).

If the connection breaks while the command runs, that server's result has
error code CONNECTION_LOST (exit 4) and the output that came so far: the
command may still be running there, or may have finished. Check with a
read-only command before running it again. For long tasks over a shaky link
use ` + "`komando job start` and `komando job wait`" + `: they survive a drop.

Destructive commands (rm -rf /, mkfs, reboot, DROP DATABASE, ...) are blocked
unless you pass --allow-dangerous. A protected server needs --yes; with
--read-only it skips --yes for commands komando knows only read.`,
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
					return localFileErr("FILE_NOT_FOUND", err, "check the --stdin-file path")
				}
				// the input may be a script (bash -s): the policy reads it
				// like the command, as script does with its file
				if err := guardBody(string(stdin)); err != nil {
					return err
				}
			}
			mutating, err := execReadOnly(args[0], command, stdin, o, readOnly)
			if err != nil {
				return err
			}
			return runFleet(cmd.Context(), "exec", args[0], command, stdin, o, mutating)
		},
	}
	o.bind(c)
	c.Flags().StringVarP(&cmdStr, "cmd", "c", "", "the command as one string (instead of words after --)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare that the command only looks (protected servers: no --yes for commands komando knows read)")
	return c
}

// execReadOnly is exec's --read-only check: a command that changes
// something is refused, and mutating says whether a protected target still
// needs --yes. A Windows target is checked as PowerShell.
func execReadOnly(target, command string, stdin []byte, o execOpts, readOnly bool) (mutating bool, err error) {
	if !readOnly {
		return true, nil
	}
	if win, err := targetWindows(target); err != nil || win {
		if err != nil {
			return true, err
		}
		return psReadOnlyCheck(command)
	}
	// bash -s alone runs its input, so the input is checked as its script;
	// any other command is checked itself, and its input is data (a CSV
	// for wc, SQL for psql)
	checked := command
	if o.stdinFile != "" && stdinShell(command) {
		checked = string(stdin)
		if err := checkReadOnlyEnv(checked, o.env); err != nil {
			return true, err
		}
	} else if err := checkReadOnlyEnv(command, o.env); err != nil {
		return true, err
	} else if w := sqlInputWrite(command, stdin); w != "" {
		if err := readOnlyStop(w); err != nil {
			return true, err
		}
	}
	// the denylist passed; a protected target still needs --yes unless
	// komando knows the command only reads (allowlist)
	return readOnlyMutates(checked, o.env), nil
}

func scriptCmd() *cobra.Command {
	var o execOpts
	var interpreter string
	var readOnly bool
	var argsList []string
	c := &cobra.Command{
		Use:   "script TARGET FILE",
		Short: "Run a script from this computer on servers (nothing on disk)",
		Example: `  komando script @web ./deploy.sh --arg v1.2.3 --sudo
  komando script db1 ./backup.py --interpreter python3`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := readFileOrStdin(args[1])
			if err != nil {
				return localFileErr("FILE_NOT_FOUND", err, "")
			}
			if win, err := targetWindows(args[0]); err != nil || win {
				if err != nil {
					return err
				}
				return windowsScript(cmd.Context(), args, body, interpreter, argsList, o, readOnly)
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
			mutating := !readOnly
			if readOnly {
				// only a shell script can be checked: the interpreter must
				// be a plain shell (python, or tee /etc/passwd, is not),
				// and its arguments ($1 ...) are not seen by the check
				if len(argsList) > 0 {
					if err := readOnlyStop("--arg values fill in $1 ... when the script runs; put them in the script instead"); err != nil {
						return err
					}
				} else if !stdinShell(command) {
					if err := readOnlyStop("the interpreter " + interpreter + " is not a shell; only shell scripts can be --read-only"); err != nil {
						return err
					}
				}
				if err := checkReadOnlyEnv(string(body), o.env); err != nil {
					return err
				}
				// a protected target still needs --yes unless komando knows
				// every command in the script only reads (allowlist)
				mutating = readOnlyMutates(string(body), o.env)
			}
			return runFleet(cmd.Context(), "script", args[0], command, body, o, mutating)
		},
	}
	o.bind(c)
	c.Flags().StringVar(&interpreter, "interpreter", "", "interpreter on the server (default: from the #! line, else sh)")
	c.Flags().StringArrayVar(&argsList, "arg", nil, "argument passed to the script (repeatable)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "declare that the shell script only looks (protected servers: no --yes when komando knows every command reads)")
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

// fleetDryRun is runFleet's --dry-run: what would run on each host.
func fleetDryRun(name string, hosts []*store.Host, req sshx.RunRequest, o execOpts, stdinBytes int, guardErr error) {
	plans := []map[string]any{}
	for _, h := range hosts {
		full, _, err := sshx.BuildCommand(&sshx.Client{Host: h}, req)
		if err != nil {
			full = "<error: " + err.Error() + ">"
		}
		if o.display != "" {
			full = o.display
		}
		plans = append(plans, map[string]any{"host": h.Name, "address": h.Address, "remote_command": full, "stdin_bytes": stdinBytes})
	}
	res := map[string]any{"would_run": plans}
	if guardErr != nil {
		res["would_be_blocked"] = toErr(guardErr)
	} else if b := out.P.Blocked(); b != nil {
		res["would_be_blocked"] = b
	}
	out.P.Print(name, res, nil)
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
	if ctx, err = windowsRunCheck(ctx, name, hosts, o); err != nil {
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
	env, err := parseEnvTo(o.env, hosts)
	if err != nil {
		return err
	}
	req := sshx.RunRequest{Command: command, Sudo: o.sudo || o.sudoUser != "", SudoUser: o.sudoUser, Env: env, Dir: o.dir,
		Stdin: stdin, Timeout: cmdTimeout(st), MaxOutput: maxOutput(st), PTY: o.pty}

	if g.dryRun {
		fleetDryRun(name, hosts, req, o, len(stdin), guardErr)
		return nil
	}

	follow := o.follow || (o.stream && name == "logs") // logs --follow
	if follow {
		s := statusLine{What: "following logs", Target: strings.Join(hostNames(hosts), ", "), Tail: "Ctrl-C stops"}
		if len(hosts) == 1 {
			s.Route = hostRoute(st, hosts[0])
		}
		for _, h := range hosts {
			s.Protected = s.Protected || protectedHost(st, h)
		}
		showStatus(s)
	}
	var mu sync.Mutex
	var failed bool
	run := func(ctx context.Context, c *sshx.Client) (any, error) {
		if o.failFast {
			mu.Lock()
			f := failed
			mu.Unlock()
			if f {
				return nil, out.Errf(out.ExitError, "SKIPPED", "run without --fail-fast to reach every server", "skipped: another server failed first, and --fail-fast is on")
			}
		}
		r := req
		host := c.Host.Name
		// output is shown by whole lines: a secret split across two reads
		// is still one piece when it is redacted
		bufs := map[string]*lineBuffer{"stdout": {}, "stderr": {}}
		show := func(stream, text string) { // mu held
			if text == "" {
				return
			}
			if out.P.Format == "text" { // a person: plain lines, marked by server when there are several
				w := os.Stdout
				if stream == "stderr" {
					w = os.Stderr
				}
				for _, line := range strings.SplitAfter(out.P.Redact(text), "\n") {
					if line == "" {
						continue
					}
					if len(hosts) > 1 {
						line = "[" + host + "] " + line
					}
					fmt.Fprint(w, out.SafeText(line))
				}
				return
			}
			out.P.Event(map[string]any{"event": "output", "host": host, "stream": stream, "data": text})
		}
		if o.stream {
			r.Stream = func(stream string, chunk []byte) {
				mu.Lock()
				defer mu.Unlock()
				if b := bufs[stream]; b != nil {
					show(stream, b.add(chunk))
				}
			}
		}
		res, err := sshx.Run(ctx, c, r)
		if o.stream {
			mu.Lock()
			show("stdout", bufs["stdout"].flush())
			show("stderr", bufs["stderr"].flush())
			mu.Unlock()
		}
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
				results = append(results, outcome{Host: h, Err: out.Errf(out.ExitError, "SKIPPED", "run without --fail-fast to reach every server", "skipped: another server failed first, and --fail-fast is on")})
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
			// a lost connection keeps what the command printed before it broke
			hr.RunResult, _ = r.Value.(*sshx.RunResult)
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

// lineBuffer holds streamed output until a line is complete, so that a
// secret split across two reads is redacted as one piece. A private key
// waits for its END line, up to pemHold: a real key is far shorter, so
// past that the BEGIN line was only a mention (a log line, a grep). Then
// the key-like lines after it are hidden and the rest goes out. Past
// streamCap without a line end, all but the last streamKeep bytes go out
// (a vault value is shorter than that).
type lineBuffer struct{ buf []byte }

const (
	streamCap  = 256 << 10
	streamKeep = 4 << 10
	pemHold    = 16 << 10
)

var (
	pemBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
	pemEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----`)
	// pemBody is a line a key can have: base64, or a header (Proc-Type: ...)
	pemBody = regexp.MustCompile(`^([A-Za-z0-9+/=]{0,100}|[A-Za-z-]+: .*)\r?$`)
)

// add takes a chunk and returns the text that is ready to show.
func (l *lineBuffer) add(chunk []byte) string {
	l.buf = append(l.buf, chunk...)
	var ready strings.Builder
	for {
		cut := bytes.LastIndexByte(l.buf, '\n') + 1
		open := -1 // where the line of an open key starts
		if locs := pemBegin.FindAllIndex(l.buf[:cut], -1); len(locs) > 0 {
			last := locs[len(locs)-1]
			if !pemEnd.Match(l.buf[last[1]:cut]) {
				open = bytes.LastIndexByte(l.buf[:last[0]], '\n') + 1
			}
		}
		if open >= 0 && cut-open > pemHold { // a mention, not a key
			ready.Write(l.buf[:open])
			ready.WriteString("[hidden: private key]\n")
			rest := l.buf[open:]
			rest = rest[bytes.IndexByte(rest, '\n')+1:] // the BEGIN line
			for {
				nl := bytes.IndexByte(rest, '\n')
				if nl < 0 || !pemBody.Match(rest[:nl]) {
					break
				}
				rest = rest[nl+1:]
			}
			l.buf = append(l.buf[:0], rest...)
			continue
		}
		if open >= 0 {
			cut = open
		}
		if len(l.buf) > streamCap {
			cut = max(cut, len(l.buf)-streamKeep)
		}
		ready.Write(l.buf[:cut])
		l.buf = append(l.buf[:0], l.buf[cut:]...)
		return ready.String()
	}
}

// flush returns what is left, at the end of the run.
func (l *lineBuffer) flush() string {
	s := string(l.buf)
	l.buf = nil
	return s
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
	return probeText(ctx, name, target, command, sudo, parse, nil)
}

// probeRow is one host's answer to a probe.
type probeRow struct {
	Host     string     `json:"host"`
	OK       bool       `json:"ok"`
	Data     any        `json:"data,omitempty"`
	ExitCode *int       `json:"exit_code,omitempty"`
	Stderr   string     `json:"stderr,omitempty"`
	Error    *out.Error `json:"error,omitempty"`
}

type probeData struct {
	Results []probeRow   `json:"results"`
	Summary fleetSummary `json:"summary"`
}

// probeTexter gives a probe its own -o text layout; the JSON is the same.
type probeTexter struct {
	probeData
	text func(probeData) string
}

func (p probeTexter) Text() string { return p.text(p.probeData) }

// probeText is probe with a text layout of its own (nil: the generic one).
func probeText(ctx context.Context, name, target, command string, sudo bool, parse func(h *store.Host, stdout string) (any, error), text func(probeData) string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	winCommand, onWindows := windowsProbes[name]
	if ctx, err = windowsGate(ctx, name, hosts, onWindows); err != nil {
		return err
	}
	if g.dryRun {
		out.P.Print(name, map[string]any{"hosts": hostNames(hosts), "would_run": command}, nil)
		return nil
	}
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		cmd := command
		if c.Host.Windows() {
			cmd = winCommand
		}
		return sshx.Run(ctx, c, sshx.RunRequest{Command: cmd, Sudo: sudo, Timeout: cmdTimeout(st), MaxOutput: maxOutput(st)})
	})
	data := probeData{Results: []probeRow{}}
	worst := 0
	var fails []hostFail
	for _, o := range res {
		r := probeRow{Host: o.Host.Name}
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
				if r.Error != nil && r.Error.Exit != 0 {
					exit = r.Error.Exit // the parser named the problem (NXDOMAIN, closed port ...): its code wins
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
	var shown any = data
	if text != nil {
		shown = probeTexter{data, text}
	}
	return finishFleet(name, shown, runSummary{fleetSummary: data.Summary}, worst, fails)
}
