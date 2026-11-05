package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

type RunRequest struct {
	Command   string
	Sudo      bool
	SudoUser  string
	Env       map[string]string
	NoEnv     bool // leave out the exports (job start writes them to a private file instead)
	Dir       string
	Stdin     []byte
	Timeout   time.Duration
	MaxOutput int
	PTY       bool
	// Stream, when set, receives output chunks as they arrive (follow mode).
	Stream func(stream string, chunk []byte)
}

type RunResult struct {
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	Signal          string `json:"signal,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
}

// Q single-quotes s for POSIX sh.
func Q(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvKey reports whether k can be exported as a shell variable. The key
// goes into the command line unquoted, so anything else could inject a command.
func ValidEnvKey(k string) bool { return envKeyRe.MatchString(k) }

// EnvExports is the "export K='v'; " prefix for the host's env and extra.
// A value written secret:NAME is read from the vault here, so it never
// passes through the agent (and output hides vault values too).
func EnvExports(c *Client, extra map[string]string) (string, error) {
	env := map[string]string{}
	if c != nil && c.Host != nil {
		for k, v := range c.Host.Env {
			env[k] = v
		}
	}
	for k, v := range extra {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		if !ValidEnvKey(k) {
			return "", fmt.Errorf("environment variable name %q is not valid (use letters, digits and _)", k)
		}
		v := env[k]
		if strings.HasPrefix(v, "secret:") {
			s, err := vault.Resolve(v)
			if err != nil {
				return "", err
			}
			v = s
		}
		sb.WriteString("export " + k + "=" + Q(v) + "; ")
	}
	return sb.String(), nil
}

// sudoPrompt and sudoReady let Run tell, from stderr, whether sudo asks for
// the password and when the command itself has started. The password is
// written only after the prompt, and the command's stdin only after the
// ready mark, so neither ends up in the other.
const (
	sudoPrompt = "[komando-sudo-password]"
	sudoReady  = "\x1ekomando-sudo-ok"
)

// BuildCommand assembles the final remote shell line: env exports, cd,
// sudo wrapping. Exposed so --dry-run can show exactly what would run.
// sudoPass is the sudo password Run feeds on request, or nil.
func BuildCommand(c *Client, r RunRequest) (cmd string, sudoPass []byte, err error) {
	var sb strings.Builder
	if !r.NoEnv {
		exports, err := EnvExports(c, r.Env)
		if err != nil {
			return "", nil, err
		}
		sb.WriteString(exports)
	}
	if r.Dir != "" {
		sb.WriteString("cd " + Q(r.Dir) + " && ")
	}
	sb.WriteString(r.Command)
	inner := sb.String()
	if !r.Sudo {
		return inner, nil, nil
	}
	userPart := ""
	if r.SudoUser != "" {
		userPart = "-u " + Q(r.SudoUser) + " "
	}
	if c != nil && c.Host != nil && c.Host.SudoRef != "" {
		pw, err := vault.Resolve(c.Host.SudoRef)
		if err != nil {
			return "", nil, err
		}
		inner = `printf '\036komando-sudo-ok\n' >&2; ` + inner
		return "sudo -S -p " + Q(sudoPrompt) + " " + userPart + "sh -c " + Q(inner), []byte(pw + "\n"), nil
	}
	return "sudo -n " + userPart + "sh -c " + Q(inner), nil, nil
}

type limitedBuf struct {
	buf       bytes.Buffer
	max       int
	truncated bool
	name      string
	stream    func(string, []byte)
}

func (l *limitedBuf) Write(p []byte) (int, error) {
	if l.stream != nil {
		cp := append([]byte(nil), p...)
		l.stream(l.name, cp)
	}
	if l.max <= 0 {
		l.buf.Write(p)
		return len(p), nil
	}
	room := l.max - l.buf.Len()
	if room <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		l.buf.Write(p[:room])
		l.truncated = true
		return len(p), nil
	}
	l.buf.Write(p)
	return len(p), nil
}

// Run executes a command and never returns an error for a non-zero exit:
// that is reported in RunResult.ExitCode. err is for transport failures.
func Run(ctx context.Context, c *Client, r RunRequest) (*RunResult, error) {
	start := time.Now()
	cmd, sudoPass, err := BuildCommand(c, r)
	if err != nil {
		return nil, err
	}
	sess, err := c.NewSession()
	if err != nil {
		if c.lost() {
			return nil, lostError(c, false)
		}
		return nil, err
	}
	defer sess.Close()
	if r.PTY {
		_ = sess.RequestPty("xterm", 40, 200, ssh.TerminalModes{ssh.ECHO: 0})
	}
	stdout := &limitedBuf{max: r.MaxOutput, name: "stdout", stream: r.Stream}
	stderr := &limitedBuf{max: r.MaxOutput, name: "stderr", stream: r.Stream}
	sess.Stdout, sess.Stderr = stdout, stderr
	var gate *sudoGate
	switch {
	case sudoPass != nil:
		if r.PTY { // a terminal merges stderr into stdout
			gate = newSudoGate(stdout, sudoPass, r.Stdin)
			sess.Stdout = gate
		} else {
			gate = newSudoGate(stderr, sudoPass, r.Stdin)
			sess.Stderr = gate
		}
		defer gate.close()
		sess.Stdin = gate.stdin
	case r.Stdin != nil:
		sess.Stdin = bytes.NewReader(r.Stdin)
	}
	if err := sess.Start(cmd); err != nil {
		if c.lost() {
			// the request to start it went out: it may have started
			return res0(start, stdout, stderr), lostError(c, true)
		}
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	var timeoutC <-chan time.Time
	if r.Timeout > 0 {
		t := time.NewTimer(r.Timeout)
		defer t.Stop()
		timeoutC = t.C
	}
	res := &RunResult{}
	select {
	case err = <-done:
	case <-timeoutC:
		res.TimedOut = true
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		err = nil
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		res.ExitCode = 124
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		sess.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		var ee *ssh.ExitError
		var me *ssh.ExitMissingError
		switch {
		case errors.As(err, &ee):
			res.ExitCode = ee.ExitStatus()
			res.Signal = ee.Signal()
		case c.lost():
			// the connection broke before the exit code came: what the
			// command printed so far goes with the error
			if gate != nil {
				gate.flush()
			}
			return res0(start, stdout, stderr), lostError(c, true)
		case errors.As(err, &me):
			res.ExitCode = -1
		default:
			return nil, err
		}
	}
	if gate != nil {
		gate.flush()
	}
	res.Stdout, res.Stderr = stdout.buf.String(), stderr.buf.String()
	if strings.HasPrefix(res.Stderr, "sudo: a password is required") || strings.Contains(res.Stderr, "sudo: a terminal is required") {
		res.Stderr += "\n[komando] hint: sudo needs a password; set it with `komando host edit <host> --sudo-ref secret:NAME`"
	}
	res.StdoutTruncated, res.StderrTruncated = stdout.truncated, stderr.truncated
	res.DurationMS = time.Since(start).Milliseconds()
	return res, nil
}

// lost reports a connection that broke: closed for silence by keepalive,
// or no longer answering.
func (c *Client) lost() bool {
	if c == nil || c.Client == nil {
		return false
	}
	return c.silent.Load() || !answers(c.Client, 5*time.Second)
}

// lostError is CONNECTION_LOST. started: the command may have run (or
// still runs) on the server; else it never started.
func lostError(c *Client, started bool) error {
	name := "the server"
	if c.Host != nil && c.Host.Name != "" {
		name = c.Host.Name
	}
	why := ""
	if c.silent.Load() {
		why = fmt.Sprintf(" (no answer from the server for about %s)", 2*keepaliveEvery())
	}
	if !started {
		return out.Errf(out.ExitConnect, "CONNECTION_LOST", "check the link with `komando test "+name+"`, then run it again",
			"the connection to %s was lost before the command started%s; it did not run", name, why)
	}
	return out.Errf(out.ExitConnect, "CONNECTION_LOST",
		"do not just run it again: first check on the server with a read-only command whether it finished (its log, `ps`, the change it makes), e.g. `komando exec "+name+" --read-only -- 'ps -ef'`; for long tasks over a shaky link use `komando job start` and `komando job wait`, which survive a dropped connection",
		"the connection to %s was lost while the command was running%s; the command may still be running there, or it may have finished: komando cannot tell", name, why)
}

// res0 is what came before the connection broke. The exit code is not
// known: -1.
func res0(start time.Time, stdout, stderr *limitedBuf) *RunResult {
	return &RunResult{ExitCode: -1, Stdout: stdout.buf.String(), Stderr: stderr.buf.String(),
		StdoutTruncated: stdout.truncated, StderrTruncated: stderr.truncated, DurationMS: time.Since(start).Milliseconds()}
}

// sudoGate sits on the stderr of a "sudo -S" session. It answers the first
// password prompt, releases the command's stdin once the ready mark shows
// that sudo let the command start, and removes both markers from stderr.
type sudoGate struct {
	mu      sync.Mutex
	out     io.Writer
	pending []byte
	ready   bool
	prompts int
	events  chan bool // true = ready, false = prompt
	done    chan struct{}
	stdin   *io.PipeReader
	pw      *io.PipeWriter
}

func newSudoGate(out io.Writer, pass, stdin []byte) *sudoGate {
	pr, pw := io.Pipe()
	g := &sudoGate{out: out, events: make(chan bool, 4), done: make(chan struct{}), stdin: pr, pw: pw}
	go func() {
		defer pw.Close()
		for {
			select {
			case <-g.done:
				return
			case ready := <-g.events:
				if ready {
					_, _ = pw.Write(stdin)
					return
				}
				if _, err := pw.Write(pass); err != nil {
					return
				}
			}
		}
	}()
	return g
}

func (g *sudoGate) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ready {
		return g.out.Write(p)
	}
	g.pending = append(g.pending, p...)
	for {
		if i := bytes.Index(g.pending, []byte(sudoPrompt)); i >= 0 {
			g.pending = append(g.pending[:i], g.pending[i+len(sudoPrompt):]...)
			g.prompts++
			if g.prompts > 1 {
				// the password was wrong: give sudo end of input instead of a hang
				g.pw.Close()
			} else {
				g.signal(false)
			}
			continue
		}
		if i := bytes.Index(g.pending, []byte(sudoReady)); i >= 0 {
			j := i + len(sudoReady)
			if j < len(g.pending) && g.pending[j] == '\r' {
				j++
			}
			if j == len(g.pending) {
				return len(p), nil // the line break may still come
			}
			if g.pending[j] == '\n' {
				j++
			}
			g.pending = append(g.pending[:i], g.pending[j:]...)
			g.ready = true
			g.signal(true)
			rest := g.pending
			g.pending = nil
			if _, err := g.out.Write(rest); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}
}

func (g *sudoGate) signal(ready bool) {
	select {
	case g.events <- ready:
	default:
	}
}

// flush passes on what sudo wrote when the command never started.
func (g *sudoGate) flush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i := bytes.Index(g.pending, []byte(sudoReady)); i >= 0 {
		g.pending = g.pending[:i] // only a "\r" can follow the mark here
	}
	if len(g.pending) > 0 {
		_, _ = g.out.Write(g.pending)
		g.pending = nil
	}
}

func (g *sudoGate) close() {
	close(g.done)
	g.stdin.Close()
}

// Output is a convenience for internal probes: run and return trimmed stdout.
func Output(ctx context.Context, c *Client, cmd string, timeout time.Duration) (string, int, error) {
	r, err := Run(ctx, c, RunRequest{Command: cmd, Timeout: timeout, MaxOutput: 4 << 20})
	if err != nil {
		return "", -1, err
	}
	return strings.TrimRight(r.Stdout, "\n"), r.ExitCode, nil
}

// Pipe runs cmd and streams stdin and stdout without buffering them, for
// transfers too large for Run (database dumps). stderr is kept up to 64 KiB
// for error messages. It returns the remote exit code.
func Pipe(ctx context.Context, c *Client, cmd string, stdin io.Reader, stdout io.Writer) (int, string, error) {
	sess, err := c.NewSession()
	if err != nil {
		return -1, "", err
	}
	defer sess.Close()
	stderr := &limitedBuf{max: 64 << 10, name: "stderr"}
	sess.Stdin, sess.Stdout, sess.Stderr = stdin, stdout, stderr
	if err := sess.Start(cmd); err != nil {
		return -1, "", err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		sess.Close()
		return -1, stderr.buf.String(), ctx.Err()
	}
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0, stderr.buf.String(), nil
	case errors.As(err, &ee):
		return ee.ExitStatus(), stderr.buf.String(), nil
	}
	return -1, stderr.buf.String(), err
}
