package cli

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/execsession"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// A run in a session on a Windows server (design note 3.3). The scripts are
// komando's own (execsession, the *_ps files); only the checked session ID
// and numbers go into their text. The command, the env and the input travel
// as base64 lines on the bootstrap's input (the "data" rule of C447).

// beginWindows is the Windows start of a run: one call that sweeps old
// folders, makes this session's folder and starts the run, then the facts
// it printed. Whatever the sweep removed is forgotten here. ErrNoFolder
// is the one error after which the caller may run without a session.
func (s *sessionRun) beginWindows(cl *call, ctx context.Context, c *sshx.Client, r sshx.RunRequest, id string) (execsession.Facts, error) {
	host := c.Host.Name
	// the command as a plain Windows exec builds it: the working folder, the
	// command and the trailer that gives the exit code; the env goes in its
	// own file
	body, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: r.Command, Dir: r.Dir, NoEnv: true})
	if err != nil {
		return execsession.Facts{}, err
	}
	pairs, err := sshx.EnvPairs(c, r.Env)
	if err != nil {
		return execsession.Facts{}, err
	}
	var env []execsession.EnvVar // nil: no env file
	for _, p := range pairs {
		env = append(env, execsession.EnvVar{Key: p.Key, Value: p.Value})
	}
	script, input, err := execsession.BeginScriptPS(execsession.StartPS{ID: id, Command: body, Env: env, Stdin: r.Stdin,
		LogMax: s.opts.logMax, Timeout: r.Timeout}, hostSessions(host))
	if err != nil {
		return execsession.Facts{}, err
	}
	b, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, NoEnv: true, Stdin: input, Timeout: 30 * time.Second, MaxOutput: 64 << 10})
	if err != nil {
		return execsession.Facts{}, err
	}
	stdout := strings.ReplaceAll(b.Stdout, "\r\n", "\n")
	forgetSessions(cl, host, execsession.Swept(stdout, id))
	return execsession.ReadStartPS(host, b.ExitCode, stdout, b.Stderr, id)
}

// readOutputMax is the most one read call may print: the log piece and,
// on Windows, its base64 form.
func readOutputMax(windows bool) int {
	if windows {
		return base64.StdEncoding.EncodedLen(execsession.ReadMaxPS) + 4<<10
	}
	return execsession.ReadMax + 4<<10
}

// removeScriptFor is the remove of session id on h's own system.
func removeScriptFor(h *store.Host, id string, rec *store.ExecSession) (string, error) {
	if h.Windows() {
		return execsession.RemoveScriptPS(id, rec)
	}
	return execsession.RemoveScript(id, rec)
}

// removeExitFor maps a remove's exit on h's own system.
func removeExitFor(h *store.Host, id string, exit int) error {
	if h.Windows() {
		return execsession.RemoveExitPS(h.Name, id, exit)
	}
	return execsession.RemoveExit(h.Name, id, exit)
}

// stopWindows is exec --attach ID --stop on a Windows server. Windows has
// no signals: --signal is refused before any connection (a signal given
// explicitly, whichever it is). The stop is built from this computer's
// record alone and ends the run's process tree (taskkill /T); the result
// lists the PIDs ended and what a stop cannot promise.
func stopWindows(cl *call, ctx context.Context, st *store.State, h *store.Host, id, sig string, sigGiven bool) error {
	if sigGiven {
		if err := execsession.SignalPS(sig); err != nil {
			return err
		}
	}
	rt, err := readRuntime()
	if err != nil {
		return err
	}
	rec, err := execsession.ForStop(rt, h.Name, id)
	if err != nil {
		return err
	}
	script, err := execsession.StopScriptPS(rec)
	if err != nil {
		return err
	}
	shown := shellLine([]string{"--attach", id, "--stop"})
	r, err := changeSession(cl, ctx, st, h, rec, id, shown, script, nil, map[string]any{"stop": "taskkill", "pid": rec.PID})
	if err != nil || r == nil {
		return err
	}
	if err := execsession.StopExitPS(h.Name, id, r.ExitCode, r.Stderr); err != nil {
		return err
	}
	pids, err := execsession.ParseStopPS(r.Stdout, id)
	if err != nil {
		return err
	}
	cl.out.Print("exec", sessionChange{Session: id, Host: h.Name, PIDs: pids, Limit: execsession.StopLimitPS}, nil)
	return nil
}
