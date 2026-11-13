package cli

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// scriptOpts are exec's --script flags.
type scriptOpts struct {
	file, interpreter string
	args              []string
}

func (so *scriptOpts) bind(c *cobra.Command) {
	c.Flags().StringVar(&so.interpreter, "interpreter", "", "with --script: the interpreter on the server (default: from the #! line, else sh)")
	c.Flags().StringArrayVar(&so.args, "arg", nil, "with --script: an argument for the script, $1 ... (repeatable)")
}

// runScript runs a script from this computer on every server target picks:
// the file goes to the interpreter as stdin, so nothing is left on disk.
func runScript(ctx context.Context, target string, so scriptOpts, o execOpts, readOnly bool) error {
	if o.stdinFile != "" || o.pty {
		return out.Usage("--script sends the file as the script's input, so --stdin-file and --pty do not go with it; read other files inside the script")
	}
	body, err := readFileOrStdin(so.file)
	if err != nil {
		return localFileErr("FILE_NOT_FOUND", err, "")
	}
	if err := hiddenInInput(so.file, body); err != nil {
		return err
	}
	noteApprovalBody(scriptLabel("the script", so.file), body)
	argsList, interpreter := so.args, so.interpreter
	if win, err := targetWindows(target); err != nil || win {
		if err != nil {
			return err
		}
		return windowsScript(ctx, target, so.file, body, interpreter, argsList, o, readOnly)
	}
	if interpreter == "" {
		interpreter = shebangInterpreter(string(body))
	}
	command := scriptCommand(interpreter, argsList)
	if so.file != "-" { // stdin is gone by then: no line to copy
		js := []string{"--script", so.file}
		if so.interpreter != "" {
			js = append(js, "--interpreter", so.interpreter)
		}
		o.jobScript = shellLine(append(js, scriptArgsShown(argsList)...))
	}
	if err := guardBody(string(body)); err != nil {
		return err
	}
	mutating := !readOnly
	if readOnly {
		if mutating, err = scriptReadOnly(string(body), interpreter, argsList, o.env); err != nil {
			return err
		}
	}
	return runFleet(ctx, "exec", target, command, body, o, mutating)
}

// scriptReadOnly is --read-only for a script (exec --script, job start
// --script): a script that changes something is refused, and mutating says
// whether a protected target still needs --yes.
func scriptReadOnly(body, interpreter string, args, env []string) (mutating bool, err error) {
	// only a shell script can be checked: the interpreter must be a plain
	// shell (python, or tee /etc/passwd, is not), and its arguments ($1
	// ...) are not seen by the check
	if len(args) > 0 {
		if err := readOnlyStop("--arg values fill in $1 ... when the script runs; put them in the script instead"); err != nil {
			return true, err
		}
	} else if !stdinShell(scriptCommand(interpreter, nil)) {
		if err := readOnlyStop("the interpreter " + interpreter + " is not a shell; only shell scripts can be --read-only"); err != nil {
			return true, err
		}
	}
	if err := checkReadOnlyEnv(body, env); err != nil {
		return true, err
	}
	// a protected target still needs --yes unless komando knows every
	// command in the script only reads (allowlist)
	return readOnlyMutates(body, env), nil
}

// scriptArgsShown are --arg values as they show in a job's command.
func scriptArgsShown(args []string) []string {
	var shown []string
	for _, a := range args {
		shown = append(shown, "--arg", a)
	}
	return shown
}

// scriptCommand is how an interpreter reads a script from stdin, with
// arguments: POSIX shells take "-s -- ARGS", the others "- ARGS" (perl,
// python, ruby, node and php all read "-" as stdin).
func scriptCommand(interpreter string, args []string) string {
	base := interpreter
	if f := strings.Fields(interpreter); len(f) > 0 {
		base = path.Base(f[0])
		if i := envProgram(f); i > 0 {
			base = path.Base(f[i])
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

// jobStartLine is the job start command that runs what exec ran on host,
// with the same --sudo, --sudo-user, --dir, --env and --stdin-file, and
// --script for a script. Input from komando's own stdin cannot be sent
// again, and job start has no pty, so a run with one of those gets "",
// and so does any command but exec: module commands build their own
// scripts.
func jobStartLine(name, host, command string, stdin []byte, o execOpts) string {
	piped := stdin != nil && o.jobScript == "" && (o.stdinFile == "" || o.stdinFile == "-")
	if name != "exec" || piped || o.pty || o.display != "" {
		return ""
	}
	parts := []string{"komando", "job", "start", host}
	if o.sudo {
		parts = append(parts, "--sudo")
	}
	if o.sudoUser != "" {
		parts = append(parts, "--sudo-user", o.sudoUser)
	}
	if o.dir != "" {
		parts = append(parts, "--dir", o.dir)
	}
	for _, e := range o.env {
		parts = append(parts, "--env", e)
	}
	if o.jobScript != "" {
		return shellLine(parts) + " " + o.jobScript
	}
	if o.stdinFile != "" {
		parts = append(parts, "--stdin-file", o.stdinFile)
	}
	return shellLine(parts) + " -- " + sshx.Q(command)
}

// execTimeoutErr is a server's TIMEOUT; line, when exec can name it, is
// the job start that runs the same thing as a background job.
func execTimeoutErr(line string, after time.Duration) *out.Error {
	e := out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout or use `komando job start` for long tasks", "command timed out after %s", after)
	if line != "" {
		e.Hint = "raise --timeout, or run it as a background job that outlives the connection: `" + line + "`"
	}
	return e
}

// lostJobHint adds the job start line to a CONNECTION_LOST hint: a job
// survives the next drop.
func lostJobHint(e *out.Error, line string) {
	if line != "" && e != nil && e.Code == "CONNECTION_LOST" {
		e.Hint += "; over a shaky link run it as a job, which survives a drop: `" + line + "`"
	}
}
