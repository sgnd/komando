package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// opsSpec is one module command (svc, logs, pkg, net, user, cron) run on a
// fleet, whose output komando reads: the parser sees stdout, stderr and the
// exit code, so it can turn "unit not found" or "no systemd" into a clear
// error code even when the remote command exited 0.
type opsSpec struct {
	name, target, command string
	display               string // shown in output and the audit log instead of a long script
	sudo, mutating        bool
	// raw keeps stdout as text (logs): rows look like `exec` rows
	raw bool
	// parse turns one host's result into data; a non-nil error marks the
	// host failed with that error's code and exit code
	parse func(h *store.Host, r *sshx.RunResult) (any, *out.Error)
	// text renders one host's data for -o text (default: the generic view)
	text func(data any) string
	// preview, when set, runs under --dry-run instead of the command: a
	// read-only simulation (apt-get -s upgrade ...)
	preview string
	// timeoutAtLeast raises the command timeout (svc --wait)
	timeoutAtLeast time.Duration
	// win is the PowerShell the command runs on Windows servers (empty:
	// the command does not work there), and winParse reads its result
	win      string
	winParse func(h *store.Host, r *sshx.RunResult) (any, *out.Error)
}

type opsRow struct {
	Host       string     `json:"host"`
	OK         bool       `json:"ok"`
	Data       any        `json:"data,omitempty"`
	Stdout     *string    `json:"stdout,omitempty"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Stderr     string     `json:"stderr,omitempty"`
	TimedOut   bool       `json:"timed_out,omitempty"`
	DurationMS int64      `json:"duration_ms,omitempty"`
	Warnings   []string   `json:"warnings,omitempty"`
	Error      *out.Error `json:"error,omitempty"`
	text       string
}

type opsData struct {
	Command string       `json:"command,omitempty"`
	DryRun  bool         `json:"dry_run,omitempty"`
	Results []opsRow     `json:"results"`
	Summary fleetSummary `json:"summary"`
}

// Text shows one block per server when there are several (like the other
// fleet commands), and just the result for one server.
func (d opsData) Text() string {
	var sb strings.Builder
	multi := len(d.Results) > 1
	for _, r := range d.Results {
		indent := ""
		if multi {
			status := "ok"
			if !r.OK {
				status = "FAILED"
			}
			fmt.Fprintf(&sb, "● %s  %s\n", r.Host, status)
			indent = "  "
		}
		body := r.text
		if r.Stdout != nil {
			body = *r.Stdout
		}
		if !r.OK && r.Stdout == nil && !strings.Contains(strings.TrimSpace(body), "\n") {
			body = "" // a table with only its header says nothing next to the error
		}
		sb.WriteString(indentLines(body, indent))
		for _, w := range r.Warnings {
			if multi {
				fmt.Fprintf(&sb, "%swarning: %s\n", indent, w)
			} else {
				fmt.Fprintf(os.Stderr, "warning: %s\n", out.SafeText(w))
			}
		}
		if !r.OK && r.Stderr != "" {
			if multi {
				sb.WriteString(indentLines(r.Stderr, indent+"| "))
			} else {
				fmt.Fprintln(os.Stderr, out.SafeText(out.P.Redact(r.Stderr)))
			}
		}
		if r.Error != nil && multi { // one server: the closing line says it once
			fmt.Fprintf(&sb, "%serror [%s]: %s\n", indent, r.Error.Code, r.Error.Message)
			if r.Error.Hint != "" {
				fmt.Fprintf(&sb, "%shint: %s\n", indent, r.Error.Hint)
			}
		}
	}
	if multi {
		fmt.Fprintf(&sb, "\n%d ok, %d failed\n", d.Summary.OK, d.Summary.Failed)
	}
	return sb.String()
}

func indentLines(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix) + "\n"
}

// runOps runs spec on every server of its target, honouring policy,
// protected servers and --dry-run like `exec` does.
func runOps(ctx context.Context, spec opsSpec) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, spec.target)
	if err != nil {
		return err
	}
	if ctx, err = windowsGate(ctx, spec.name, hosts, spec.win != ""); err != nil {
		return err
	}
	shown := spec.command
	if spec.display != "" {
		shown = spec.display
	}
	guardErr := guard(st, hosts, strings.TrimSpace(spec.command+"\n"+spec.win), spec.mutating)
	if guardErr != nil && !g.dryRun {
		audit(st, spec.name, hostNames(hosts), shown, false, map[string]any{"blocked": toErr(guardErr).Code})
		return guardErr
	}
	command := spec.command
	if g.dryRun {
		if spec.preview == "" {
			opsDryRun(spec, hosts, shown, guardErr)
			return nil
		}
		command = spec.preview // read-only: shows what would change
	}
	timeout := max(cmdTimeout(st), spec.timeoutAtLeast)
	res := fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		cmd := command
		if c.Host.Windows() && g.dryRun { // a preview: never run the change itself
			return nil, notOnWindows("a --dry-run preview of "+commandWord(spec.name), []string{c.Host.Name})
		} else if c.Host.Windows() {
			cmd = spec.win
		}
		return sshx.Run(ctx, c, sshx.RunRequest{Command: cmd, Sudo: spec.sudo, Timeout: timeout, MaxOutput: maxOutput(st)})
	})
	data := opsData{Command: shown, DryRun: g.dryRun, Results: []opsRow{}}
	worst := 0
	var fails []hostFail
	for _, o := range res {
		r := opsRow{Host: o.Host.Name}
		if o.Err != nil {
			r.Error = toErr(o.Err)
			worst = worse(worst, r.Error.Exit)
		} else {
			rr := o.Value.(*sshx.RunResult)
			code := rr.ExitCode
			r.ExitCode, r.TimedOut, r.DurationMS = &code, rr.TimedOut, rr.DurationMS
			if spec.raw {
				s := rr.Stdout
				r.Stdout = &s
			}
			if parse := opsParser(spec, o.Host); parse != nil {
				d, perr := parse(o.Host, rr)
				r.Error = perr
				if w, ok := d.(opsWarnings); ok {
					r.Warnings, d = w.warnings, w.data
				}
				if s, ok := d.(string); ok && spec.raw {
					r.Stdout = &s
				} else if !spec.raw {
					r.Data = d
				}
			} else if !spec.raw {
				r.Data = rr.Stdout
			}
			switch {
			case rr.TimedOut:
				r.Error = out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout or use `komando job start` for long tasks", "command timed out")
			case r.Error != nil:
				r.Error.Exit = max(r.Error.Exit, 1)
			case rr.ExitCode != 0:
				r.Error = out.Errf(out.ExitRemote, "COMMAND_FAILED", "read stderr for the reason", "exit code %d", rr.ExitCode)
			}
			r.OK = r.Error == nil
			if !r.OK {
				r.Stderr = strings.TrimSpace(rr.Stderr)
				worst = worse(worst, r.Error.Exit)
			}
			if !spec.raw && r.Data != nil && spec.text != nil {
				r.text = spec.text(r.Data)
			} else if !spec.raw && r.Data != nil {
				r.text = renderPlain(r.Data)
			}
		}
		if r.OK {
			data.Summary.OK++
		} else {
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Host)
			code := 0
			if r.ExitCode != nil {
				code = *r.ExitCode
			}
			fails = append(fails, hostFail{host: r.Host, reason: failReason(code, r.Error), err: r.Error})
		}
		data.Results = append(data.Results, r)
	}
	data.Summary.Total = len(res)
	if !g.dryRun {
		audit(st, spec.name, hostNames(hosts), shown, data.Summary.Failed == 0, nil)
	}
	// the same closing as exec: each failed server with its own error and hint
	return finishFleet(spec.name, data, runSummary{fleetSummary: data.Summary}, worst, fails)
}

// opsDryRun is runOps' --dry-run without a preview: what would run where.
func opsDryRun(spec opsSpec, hosts []*store.Host, shown string, guardErr error) {
	plans := []map[string]any{}
	for _, h := range hosts {
		cmd := shown
		if h.Windows() && spec.win != "" && spec.display == "" {
			cmd = spec.win // what PowerShell would get, not the sh script
		}
		plans = append(plans, map[string]any{"host": h.Name, "address": h.Address, "remote_command": cmd, "sudo": spec.sudo && !h.Windows()})
	}
	res := map[string]any{"would_run": plans}
	if guardErr != nil {
		res["would_be_blocked"] = toErr(guardErr)
	} else if b := out.P.Blocked(); b != nil {
		res["would_be_blocked"] = b
	}
	out.P.Print(spec.name, res, nil)
}

// opsParser is the parser of spec's result on host h.
// A sudo that refused before the command ran is said first: there is
// nothing to parse then.
func opsParser(spec opsSpec, h *store.Host) func(h *store.Host, r *sshx.RunResult) (any, *out.Error) {
	if h.Windows() && spec.winParse != nil {
		return spec.winParse
	}
	if !spec.sudo || h.Windows() || spec.parse == nil {
		return spec.parse
	}
	return func(h *store.Host, rr *sshx.RunResult) (any, *out.Error) {
		if e := sudoProblem(h.Name, rr); e != nil {
			return nil, e
		}
		return spec.parse(h, rr)
	}
}

// opsWarnings lets a parser attach warnings (shown on stderr in text mode)
// to a successful result.
type opsWarnings struct {
	data     any
	warnings []string
}

// renderPlain is the text view of data without its own renderer: key:
// value lines.
func renderPlain(d any) string {
	switch t := d.(type) {
	case string:
		return t
	case nil:
		return ""
	}
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Sprint(d)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return string(b)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		v := m[k]
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			v = int64(f)
		}
		switch v.(type) {
		case map[string]any, []any:
			j, _ := json.Marshal(v)
			v = string(j)
		}
		fmt.Fprintf(&sb, "%s: %v\n", k, v)
	}
	return sb.String()
}

// marker finds komando's own status line ("#komando:no-systemd") in a
// script's stdout.
func marker(stdout string) string {
	for _, l := range strings.Split(stdout, "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(l), "#komando:"); ok {
			return m
		}
	}
	return ""
}

// noSystemd stops a script on servers that run without systemd (most
// containers) with a marker the parser turns into NO_SYSTEMD.
const noSystemd = "[ -d /run/systemd/system ] || { echo '#komando:no-systemd'; exit 0; }\n"

func errNoSystemd() *out.Error {
	return out.Errf(out.ExitNotFound, "NO_SYSTEMD", "this server runs without systemd (a container?); read logs with `komando logs TARGET --file PATH` or `komando docker logs`",
		"systemd is not running on this server")
}

// sudoProblem reads why `sudo -n` refused before the command ran: sudo
// wants a password komando does not have, the login user may not use it,
// or the server has no sudo (a minimal image where you log in as root).
// host names the server in the hint; "" leaves NAME (a group).
func sudoProblem(host string, rr *sshx.RunResult) *out.Error {
	if rr == nil || rr.ExitCode == 0 {
		return nil
	}
	name := host
	if name == "" {
		name = "NAME"
	}
	e := strings.ToLower(rr.Stderr)
	switch {
	case strings.Contains(e, "sudo: a password is required"), strings.Contains(e, "sudo: a terminal is required"),
		strings.Contains(e, "no tty present and no askpass"):
		return out.Errf(out.ExitRemote, "PERMISSION_DENIED",
			"a person stores the sudo password with `komando secret set "+name+"-sudo`, then runs `komando host edit "+name+" --sudo-ref secret:"+name+"-sudo`; when you log in as root, add --no-sudo",
			"sudo asks for a password komando does not have")
	case strings.Contains(e, "is not in the sudoers file"), strings.Contains(e, "is not allowed to run sudo"),
		strings.Contains(e, "may not run sudo"):
		return out.Errf(out.ExitRemote, "PERMISSION_DENIED",
			"log in as a user who may use sudo (`komando host edit "+name+" --user OTHER`), or add the login user to the sudo (Debian) or wheel (RHEL) group",
			"the login user may not use sudo")
	case rr.ExitCode == 127 && (strings.Contains(e, "sudo: not found") || strings.Contains(e, "sudo: command not found")):
		return out.Errf(out.ExitNotFound, "TOOL_MISSING",
			"when you log in as root, add --no-sudo; otherwise install sudo on the server",
			"sudo is not installed on this server")
	}
	return nil
}

// orSudo is an exitMap that names a sudo problem first, then tries next.
func orSudo(host string, next func(*sshx.RunResult) *out.Error) func(*sshx.RunResult) *out.Error {
	return func(rr *sshx.RunResult) *out.Error {
		if e := sudoProblem(host, rr); e != nil {
			return e
		}
		if next == nil {
			return nil
		}
		return next(rr)
	}
}

// soleHost is target when it names one server, "" otherwise (a group, a
// list or a pattern), for hints that name the server.
func soleHost(target string) string {
	st, err := loadState()
	if err != nil {
		return ""
	}
	if hosts, err := resolveTargets(st, target); err == nil && len(hosts) == 1 {
		return hosts[0].Name
	}
	return ""
}

// followEnded: Ctrl-C is how a person ends logs --follow, like --timeout,
// so a follow cancelled that way is no error: what came so far is the
// result, exit 0.
func followEnded(ctx context.Context, follow bool, res []outcome) []outcome {
	if !follow || !errors.Is(ctx.Err(), context.Canceled) {
		return res
	}
	for i, r := range res {
		if r.Err == nil {
			continue
		}
		rr, _ := r.Value.(*sshx.RunResult)
		if rr == nil {
			rr = &sshx.RunResult{}
		}
		rr.ExitCode, rr.TimedOut = 0, false
		res[i].Value, res[i].Err = rr, nil
	}
	return res
}
