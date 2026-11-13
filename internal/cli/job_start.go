package cli

import (
	"cmp"
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// jobSpec is what job start runs: a command, or a script from this
// computer that the job's interpreter reads as its input.
type jobSpec struct {
	command  string // what the job's shell runs
	shown    string // the command, or --script FILE ...: in job list and the audit log
	input    []byte // the script or --stdin-file: the command's input, after the env
	mutating bool   // a protected target needs a person's yes
	sudo     bool
	sudoUser string // --sudo-user: sudo -u
	dir      string // --dir
	env      map[string]string
	timeout  time.Duration // --timeout: the job is stopped after it; 0: no limit
}

// jobWhat reads job start's command or --script into a jobSpec, with the
// checks exec does: hidden values, deny rules and --read-only. stdinFile
// is --stdin-file, the command's input.
func jobWhat(args []string, cmdStr string, so scriptOpts, stdinFile string, readOnly bool, envs []string) (jobSpec, error) {
	sp := jobSpec{mutating: !readOnly}
	if so.file != "" {
		if cmdStr != "" || len(args) > 1 {
			return sp, out.Usage("give a command or --script FILE, not both")
		}
		if stdinFile != "" {
			return sp, out.Usage("--script sends the file as the script's input, so --stdin-file does not go with it; read other files inside the script")
		}
		var err error
		if sp.input, err = readFileOrStdin(so.file); err != nil {
			return sp, localFileErr("FILE_NOT_FOUND", err, "")
		}
		if err := hiddenInInput(so.file, sp.input); err != nil {
			return sp, err
		}
		noteApprovalBody(scriptLabel("the script", so.file), sp.input)
		if err := guardBody(string(sp.input)); err != nil {
			return sp, err
		}
		interpreter := cmp.Or(so.interpreter, shebangInterpreter(string(sp.input)))
		if win, err := targetWindows(args[0]); err != nil || win {
			if err == nil {
				err = out.Usage("job start --script runs on Linux and other Unix servers; on Windows use `komando exec TARGET --script FILE`")
			}
			return sp, err
		}
		if readOnly {
			if sp.mutating, err = scriptReadOnly(string(sp.input), interpreter, so.args, envs); err != nil {
				return sp, err
			}
		}
		// the interpreter reads the script as its input: nothing of it is
		// left on the server
		sp.command = scriptCommand(interpreter, so.args)
		sp.shown = shellLine(append([]string{"--script", so.file}, scriptArgsShown(so.args)...))
		return sp, nil
	}
	if so.interpreter != "" || len(so.args) > 0 {
		return sp, out.Usage("--interpreter and --arg go with --script FILE")
	}
	var err error
	if sp.command, err = commandWords(cmdStr, args[1:], "job start "+args[0]); err != nil {
		return sp, err
	}
	if strings.TrimSpace(sp.command) == "" {
		return sp, out.Usage("no command given: komando job start TARGET -- COMMAND (or --script FILE)")
	}
	if stdinFile != "" {
		if sp.input, err = readFileOrStdin(stdinFile); err != nil {
			return sp, localFileErr("FILE_NOT_FOUND", err, "check the --stdin-file path")
		}
		if err := hiddenInInput(stdinFile, sp.input); err != nil {
			return sp, err
		}
		noteApprovalBody(scriptLabel("the input", stdinFile), sp.input)
		// the input may be a script (bash -s): the policy reads it
		if err := guardBody(string(sp.input)); err != nil {
			return sp, err
		}
	}
	sp.mutating, err = execReadOnly(args[0], sp.command, sp.input, execOpts{stdinFile: stdinFile, env: envs}, readOnly)
	if err != nil {
		return sp, err
	}
	sp.shown = sp.command
	if stdinFile != "" {
		sp.shown = shellLine([]string{"--stdin-file", stdinFile}) + " -- " + sp.command
	}
	return sp, nil
}

// startJob starts one job on c and records it. The job's env exports and
// input (a script, --stdin-file) wait in private files in its folder; the
// login user's shell sends them to the command through a pipe and deletes
// each once sent. So a command run as another user (--sudo-user) gets
// them too, and none of it is ever on a command line (ps shows those to
// every user on the server).
func startJob(ctx context.Context, c *sshx.Client, sp jobSpec) (started, error) {
	id := newID("j")
	exports, err := sshx.EnvExports(c, sp.env)
	if err != nil {
		return started{}, err
	}
	inner, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: sp.command, Dir: sp.dir, NoEnv: true})
	if err != nil {
		return started{}, err
	}
	if exports != "" {
		// dd reads one byte at a time: what follows stays the command's input
		inner = `eval "$(dd bs=1 count=` + strconv.Itoa(len(exports)) + ` 2>/dev/null)"; ` + inner
	}
	run, pw, err := jobRunner(c, sp, inner)
	if err != nil {
		return started{}, err
	}
	envFile, pwFile, inFile := "", "", ""
	if exports != "" {
		envFile = sshx.SaveInput(len(exports), `"$d/env"`) + ` && `
	}
	if pw != nil {
		pwFile = sshx.SaveInput(len(pw), `"$d/pw"`) + ` && `
	}
	if sp.input != nil {
		inFile = `(umask 077; cat > "$d/in") && `
	}
	script := `u=$(umask); umask 077; d="` + jobDir(id) + `"; mkdir -p "$d" && chmod 700 "$d" && ` + envFile + pwFile + inFile + `printf '%s\n' ` + sshx.Q(sp.shown) + ` > "$d/cmd" && date -u +%s > "$d/started"; ` +
		`export d; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + sshx.Q(jobWrapper(run, sp.timeout)) + ` sh "$u" > "$d/out.log" 2>&1 < /dev/null & ` +
		`else nohup sh -c ` + sshx.Q(jobWrapper(run, sp.timeout)) + ` sh "$u" > "$d/out.log" 2>&1 < /dev/null & fi; echo $! > "$d/pid"; echo $!`
	input := append(append([]byte(exports), pw...), sp.input...)
	r, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Stdin: input, Timeout: 30 * time.Second, MaxOutput: 64 << 10})
	if err != nil {
		return started{}, err
	}
	o, code := strings.TrimSpace(r.Stdout), r.ExitCode
	pid, perr := strconv.Atoi(strings.TrimSpace(o))
	if code != 0 || perr != nil {
		return started{}, out.Errf(out.ExitRemote, "JOB_START_FAILED", "check that /bin/sh and nohup work there: `komando test TARGET`", "could not start job: %s", o)
	}
	j := &store.Job{ID: id, Host: c.Host.Name, Command: sp.shown, PID: pid, RemoteDir: jobDir(id), StartedAt: time.Now().UTC()}
	if err := store.UpdateRuntime(func(s *store.State) error { s.Jobs[id] = j; return nil }); err != nil {
		return started{}, err
	}
	return started{ID: id, Host: c.Host.Name, PID: pid, OK: true}, nil
}

// jobFeed sends the job's env and input to its command, in that order,
// deleting each file once it is sent; a sudo password goes first (pw).
func jobFeed(pw bool) string {
	f := `{ `
	if pw {
		f += `cat "$d/pw"; rm -f "$d/pw"; `
	}
	return f + `[ ! -f "$d/env" ] || { cat "$d/env"; rm -f "$d/env"; }; [ ! -f "$d/in" ] || { cat "$d/in"; rm -f "$d/in"; }; }`
}

// jobRunner is what starts the job: the feed piped into sudo (as root, or
// --sudo-user) or sh, in the background, its pid in w. With the server's
// sudo password (pw, sent to the job as input), sudo is first asked
// whether it needs one: when it does not, the password is deleted unread,
// so it can never reach the command.
func jobRunner(c *sshx.Client, sp jobSpec, inner string) (start string, pw []byte, err error) {
	sh := "sh -c " + sshx.Q(inner)
	if !sp.sudo && sp.sudoUser == "" {
		return jobFeed(false) + " | " + sh + " & w=$!", nil, nil
	}
	user := ""
	if sp.sudoUser != "" {
		user = "-u " + sshx.Q(sp.sudoUser) + " "
	}
	if c.Host.SudoRef == "" {
		return jobFeed(false) + " | sudo -n " + user + sh + " & w=$!", nil, nil
	}
	p, err := vault.Resolve(c.Host.SudoRef)
	if err != nil {
		return "", nil, err
	}
	start = `if sudo -n ` + user + `sh -c : 2>/dev/null; then rm -f "$d/pw"; ` + jobFeed(false) + ` | sudo -n ` + user + sh +
		` & w=$!; else ` + jobFeed(true) + ` | sudo -S -p '' ` + user + sh + ` & w=$!; fi`
	return start, []byte(p + "\n"), nil
}

// jobWrapper runs the job with the login's own umask ($1, so the job's
// environment gains no variable) and writes its exit code, unless the job
// was stopped (killed). With a timeout, a watcher stops the job after it
// as job kill does, the whole process group (setsid) or else the command,
// and notes "TERM timeout" so job status says why.
func jobWrapper(start string, timeout time.Duration) string {
	end := `wait $w 2>/dev/null; c=$?; `
	watch := ""
	if timeout > 0 {
		secs := strconv.Itoa(int((timeout + time.Second - 1) / time.Second))
		watch = `( trap 'kill $t 2>/dev/null; exit 0' TERM; sleep ` + secs + ` & t=$!; wait $t; ` +
			`kill -0 $w 2>/dev/null && { printf 'TERM timeout\n' > "$d/killed"; kill -TERM -$$ 2>/dev/null || kill -TERM $w; } ) & s=$!; `
		end += `kill $s 2>/dev/null; `
	}
	return `umask "$1"; ` + start + `; umask 077; ` + watch + end + `[ -f "$d/killed" ] || echo $c > "$d/exit"`
}
