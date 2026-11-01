package sshx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/vault"
)

type RunRequest struct {
	Command   string
	Sudo      bool
	SudoUser  string
	Env       map[string]string
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

// BuildCommand assembles the final remote shell line: env exports, cd,
// sudo wrapping. Exposed so --dry-run can show exactly what would run.
func BuildCommand(c *Client, r RunRequest) (cmd string, stdinPrefix []byte, err error) {
	var sb strings.Builder
	env := map[string]string{}
	if c != nil && c.Host != nil {
		for k, v := range c.Host.Env {
			env[k] = v
		}
	}
	for k, v := range r.Env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString("export " + k + "=" + Q(env[k]) + "; ")
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
		return "sudo -S -p '' " + userPart + "sh -c " + Q(inner), []byte(pw + "\n"), nil
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
	cmd, prefix, err := BuildCommand(c, r)
	if err != nil {
		return nil, err
	}
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	if r.PTY {
		_ = sess.RequestPty("xterm", 40, 200, ssh.TerminalModes{ssh.ECHO: 0})
	}
	stdout := &limitedBuf{max: r.MaxOutput, name: "stdout", stream: r.Stream}
	stderr := &limitedBuf{max: r.MaxOutput, name: "stderr", stream: r.Stream}
	sess.Stdout, sess.Stderr = stdout, stderr
	if len(prefix) > 0 || r.Stdin != nil {
		sess.Stdin = io.MultiReader(bytes.NewReader(prefix), bytes.NewReader(r.Stdin))
	}
	if err := sess.Start(cmd); err != nil {
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
		case errors.As(err, &me):
			res.ExitCode = -1
		default:
			return nil, err
		}
	}
	res.Stdout, res.Stderr = stdout.buf.String(), stderr.buf.String()
	if strings.HasPrefix(res.Stderr, "sudo: a password is required") || strings.Contains(res.Stderr, "sudo: a terminal is required") {
		res.Stderr += "\n[komando] hint: sudo needs a password; set it with `komando host edit <host> --sudo-ref secret:NAME`"
	}
	res.StdoutTruncated, res.StderrTruncated = stdout.truncated, stderr.truncated
	res.DurationMS = time.Since(start).Milliseconds()
	return res, nil
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
