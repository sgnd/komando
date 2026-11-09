package sshx

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"
)

// Windows servers run every command in PowerShell (docs/design/windows.md).
// The command line is always the same short bootstrap; the script itself
// travels on the command's input, as its first line (base64), followed by
// the values of secret environment variables and then the caller's own
// input. So the script is never on a command line (where cmd.exe cuts it at
// 8191 characters and other users could read it), and quoting is only ever
// PowerShell's.

// psBootstrap reads the script from the first input line and runs it.
// `exit N` in the script ends PowerShell with N; otherwise the script's
// own trailer (PSTrailer) sets $LASTEXITCODE; an uncaught throw ends it
// with 1. An error inside one statement does not stop the script, as in
// any PowerShell script. Out-Default writes the
// output before PowerShell exits (a table is otherwise still waiting to
// be drawn), as plain text (PowerShell 7 colours it). Input and output are
// UTF-8, not the console's code page (437 or 850 over OpenSSH).
const psBootstrap = `$ProgressPreference = 'SilentlyContinue'
if ($PSStyle) { $PSStyle.OutputRendering = 'PlainText' }
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}
try { [Console]::InputEncoding = New-Object Text.UTF8Encoding $false } catch {}
$k = [Console]::In.ReadLine()
if ($null -eq $k) { [Console]::Error.WriteLine('komando: the script did not arrive on input'); exit 125 }
$k = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($k))
$global:LASTEXITCODE = 0
& ([scriptblock]::Create($k)) | Out-Default
exit $LASTEXITCODE`

// PSTrailer ends every script: a failed last command (a cmdlet error, or a
// program that exited non-zero) makes the exit code non-zero, as in sh.
const PSTrailer = "\nif (-not $?) { if ($LASTEXITCODE) { exit $LASTEXITCODE }; exit 1 }; $global:LASTEXITCODE = 0\n"

// PSCommandLine is the program komando starts on a Windows server.
var PSCommandLine = "powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodePS(psBootstrap)

// encodePS is a script as -EncodedCommand takes it: UTF-16LE, base64.
func encodePS(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		b[2*i], b[2*i+1] = byte(r), byte(r>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// PSQ quotes s as a PowerShell string literal: in single quotes nothing is
// expanded, and a quote is doubled. PowerShell also reads the typographic
// single quotes (U+2018 to U+201B) as quotes, so they are doubled too.
func PSQ(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '‘', '’', '‚', '‛':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// PSArray is a PowerShell array of string literals: @('a', 'b').
func PSArray(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = PSQ(s)
	}
	return "@(" + strings.Join(q, ", ") + ")"
}

// windowsScript is the PowerShell script a request runs, and the input
// lines it reads before the caller's input: values from the vault, which
// stay off the script (it is shown by --dry-run and kept in no log).
func windowsScript(c *Client, r RunRequest) (script string, input []byte, err error) {
	var sb strings.Builder
	if !r.NoEnv {
		vars, err := commandEnv(c, r.Env)
		if err != nil {
			return "", nil, err
		}
		for _, v := range vars {
			if !v.secret {
				sb.WriteString("$env:" + v.key + " = " + PSQ(v.value) + "\n")
				continue
			}
			sb.WriteString("$env:" + v.key + " = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadLine()))\n")
			input = append(input, base64.StdEncoding.EncodeToString([]byte(v.value))+"\n"...)
		}
	}
	if r.Dir != "" {
		sb.WriteString("Set-Location -LiteralPath " + PSQ(r.Dir) + " -ErrorAction Stop\n")
	}
	sb.WriteString(r.Command)
	sb.WriteString(PSTrailer)
	return sb.String(), input, nil
}

// psInput is what goes on the bootstrap's input: the script line, then
// the vault values it reads.
func psInput(script string, env []byte) []byte {
	in := []byte(base64.StdEncoding.EncodeToString([]byte(script)) + "\n")
	return append(in, env...)
}

// runWindows is Run for a Windows server. There is no sudo on Windows (the
// login's own rights apply) and no terminal: both are left out.
func runWindows(ctx context.Context, c *Client, r RunRequest) (*RunResult, error) {
	start := time.Now()
	script, env, err := windowsScript(c, r)
	if err != nil {
		return nil, err
	}
	stdin := append(psInput(script, env), r.Stdin...)
	stdout := &limitedBuf{max: r.MaxOutput, name: "stdout", stream: r.Stream}
	stderr := &limitedBuf{max: r.MaxOutput, name: "stderr", stream: r.Stream}
	rctx := ctx
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	code, err := runPS(rctx, c, bytes.NewReader(stdin), stdout, stderr)
	res := &RunResult{ExitCode: code}
	switch {
	case err != nil && ctx.Err() == nil && errors.Is(rctx.Err(), context.DeadlineExceeded):
		res.TimedOut, res.ExitCode = true, 124
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		var lost *lostErr
		if errors.As(err, &lost) {
			r0 := res0(start, stdout, stderr)
			r0.Stderr = CleanPSError(r0.Stderr)
			return r0, lost.err
		}
		return nil, err
	}
	res.Stdout, res.Stderr = stdout.buf.String(), CleanPSError(stderr.buf.String())
	res.StdoutTruncated, res.StderrTruncated = stdout.truncated, stderr.truncated
	res.DurationMS = time.Since(start).Milliseconds()
	return res, nil
}

// RunPS runs a PowerShell script on a Windows server with stdin after it
// and stdout streamed, for transfers too large for Run. stderr is kept up
// to 64 KiB. It returns the script's exit code.
func RunPS(ctx context.Context, c *Client, script string, stdin io.Reader, stdout io.Writer) (int, string, error) {
	in := io.Reader(bytes.NewReader(psInput(script+PSTrailer, nil)))
	if stdin != nil {
		in = io.MultiReader(in, stdin)
	}
	stderr := &limitedBuf{max: 64 << 10, name: "stderr"}
	code, err := runPS(ctx, c, in, stdout, stderr)
	var lost *lostErr
	if errors.As(err, &lost) {
		err = lost.err
	}
	return code, CleanPSError(stderr.buf.String()), err
}

// lostErr carries CONNECTION_LOST from runPS, with what came before it.
type lostErr struct{ err error }

func (e *lostErr) Error() string { return e.err.Error() }

// runPS starts the bootstrap over SSH, feeds it in and returns its exit
// code. When ctx ends the session is closed, which ends PowerShell.
func runPS(ctx context.Context, c *Client, in io.Reader, stdout, stderr io.Writer) (int, error) {
	if c.Win != nil {
		return c.Win.Run(ctx, PSCommandLine, in, stdout, stderr)
	}
	sess, err := c.NewSession()
	if err != nil {
		if c.lost() {
			return -1, &lostErr{lostError(c, false)}
		}
		return -1, err
	}
	defer sess.Close()
	sess.Stdin, sess.Stdout, sess.Stderr = in, stdout, stderr
	if err := sess.Start(PSCommandLine); err != nil {
		if c.lost() {
			return -1, &lostErr{lostError(c, true)}
		}
		return -1, err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		sess.Close()
		return -1, ctx.Err()
	}
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitStatus(), nil
	case c.lost():
		return -1, &lostErr{lostError(c, true)}
	}
	return -1, err
}

var (
	clixmlString = regexp.MustCompile(`(?s)<S S="(Error|Warning)">(.*?)</S>`)
	clixmlEscape = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)
	ansiColor    = regexp.MustCompile("\x1b\\[[0-9;]*m")
)

// CleanPSError turns PowerShell's error stream back into text, without
// PowerShell 7's colours. Windows
// PowerShell writes it as CLIXML ("#< CLIXML" and XML) when its output is
// not a console, as over SSH or WinRM: the error and warning lines are
// kept, progress records are dropped.
func CleanPSError(s string) string {
	s = ansiColor.ReplaceAllString(s, "")
	i := strings.Index(s, "#< CLIXML")
	if i < 0 {
		return s
	}
	var b strings.Builder
	b.WriteString(s[:i])
	for _, m := range clixmlString.FindAllStringSubmatch(s[i:], -1) {
		t := html.UnescapeString(m[2])
		t = clixmlEscape.ReplaceAllStringFunc(t, func(x string) string {
			n, err := strconv.ParseUint(x[2:6], 16, 16)
			if err != nil {
				return x
			}
			return string(rune(n))
		})
		b.WriteString(strings.ReplaceAll(t, "\r\n", "\n"))
	}
	return b.String()
}

// isWindows reports a request for a Windows server.
func isWindows(c *Client) bool { return c != nil && c.Host.Windows() }
