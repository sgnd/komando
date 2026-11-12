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
// computer (body) that the job reads from its own folder.
type jobSpec struct {
	command  string // what the job's shell runs
	shown    string // the command, or --script FILE ...: in job list and the audit log
	body     []byte // the script, sent as input after the env and the sudo password
	mutating bool   // a protected target needs a person's yes
	sudo     bool
	dir      string
	env      map[string]string
}

// jobWhat reads job start's command or --script into a jobSpec, with the
// checks exec does: hidden values, deny rules and --read-only.
func jobWhat(args []string, cmdStr string, so scriptOpts, readOnly bool, envs []string) (jobSpec, error) {
	sp := jobSpec{mutating: !readOnly}
	if so.file != "" {
		if cmdStr != "" || len(args) > 1 {
			return sp, out.Usage("give a command or --script FILE, not both")
		}
		var err error
		if sp.body, err = readFileOrStdin(so.file); err != nil {
			return sp, localFileErr("FILE_NOT_FOUND", err, "")
		}
		if err := hiddenInInput(so.file, sp.body); err != nil {
			return sp, err
		}
		noteApprovalBody(scriptLabel("the script", so.file), sp.body)
		if err := guardBody(string(sp.body)); err != nil {
			return sp, err
		}
		interpreter := cmp.Or(so.interpreter, shebangInterpreter(string(sp.body)))
		if win, err := targetWindows(args[0]); err != nil || win {
			if err == nil {
				err = out.Usage("job start --script runs on Linux and other Unix servers; on Windows use `komando exec TARGET --script FILE`")
			}
			return sp, err
		}
		if readOnly {
			if sp.mutating, err = scriptReadOnly(string(sp.body), interpreter, so.args, envs); err != nil {
				return sp, err
			}
		}
		// the job reads the script from its file ($2), which it removes
		// once it has it open: nothing is left on the server
		sp.command = `{ rm -f "$2"; ` + scriptCommand(interpreter, so.args) + `; } < "$2"`
		sp.shown = shellLine(append([]string{"--script", so.file}, scriptArgsShown(so.args)...))
	} else {
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
		if readOnly {
			if err := checkReadOnlyEnv(sp.command, envs); err != nil {
				return sp, err
			}
			sp.mutating = readOnlyMutates(sp.command, envs)
		}
		sp.shown = sp.command
	}
	return sp, nil
}

// startJob starts one job on c and records it.
func startJob(ctx context.Context, c *sshx.Client, sp jobSpec) (started, error) {
	id := newID("j")
	// The exports go, on stdin, to a private file the job reads and
	// deletes: a command line is visible to every user on the
	// server (ps), secrets included, and a job runs for long.
	exports, err := sshx.EnvExports(c, sp.env)
	if err != nil {
		return started{}, err
	}
	inner, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: sp.command, Dir: sp.dir, NoEnv: true})
	if err != nil {
		return started{}, err
	}
	if exports != "" {
		inner = `. "$1"; rm -f "$1"; ` + inner
	}
	var pw []byte // the sudo password, sent as input, never on a command line
	pwFile := ""
	// the job's shell gets the env file as $1 and the script as $2
	shArgs := ` sh "$d/env" "$d/script"`
	switch {
	case sp.sudo && c.Host.SudoRef != "":
		p, err := vault.Resolve(c.Host.SudoRef)
		if err != nil {
			return started{}, err
		}
		pw = []byte(p + "\n")
		// The password waits in a private file. The job opens it as
		// sudo's input and deletes it at once; the command itself
		// gets no input, so it can never read the password.
		pwFile = sshx.SaveInput(len(pw), `"$d/pw"`) + ` && `
		inner = `{ rm -f "$d/pw"; sudo -S -p '' sh -c ` + sshx.Q("exec </dev/null; "+inner) + shArgs + `; } < "$d/pw"`
	case sp.sudo:
		inner = "sudo -n sh -c " + sshx.Q(inner) + shArgs
	default:
		inner = "sh -c " + sshx.Q(inner) + shArgs
	}
	// the job runs with the login's own umask ($u); its folder and files
	// (the command, its output, the pid) are the SSH user's alone
	wrapper := "( umask \"$u\"; " + inner + " ); echo $? > \"$d/exit\""
	envFile := ""
	if exports != "" {
		envFile = sshx.SaveInput(len(exports), `"$d/env"`) + ` && `
	}
	scriptFile := ""
	if sp.body != nil {
		scriptFile = `(umask 077; cat > "$d/script") && `
	}
	script := `u=$(umask); umask 077; d="` + jobDir(id) + `"; mkdir -p "$d" && chmod 700 "$d" && ` + envFile + pwFile + scriptFile + `printf '%s\n' ` + sshx.Q(sp.shown) + ` > "$d/cmd" && date -u +%s > "$d/started"; ` +
		`export d u; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + sshx.Q(wrapper) + ` > "$d/out.log" 2>&1 < /dev/null & ` +
		`else nohup sh -c ` + sshx.Q(wrapper) + ` > "$d/out.log" 2>&1 < /dev/null & fi; echo $! > "$d/pid"; echo $!`
	input := append(append([]byte(exports), pw...), sp.body...)
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
