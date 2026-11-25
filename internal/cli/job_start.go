package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/execsession"
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
func jobWhat(cl *call, args []string, cmdStr string, so scriptOpts, stdinFile string, readOnly bool, envs []string) (jobSpec, error) {
	sp := jobSpec{mutating: !readOnly}
	if so.file != "" {
		if cmdStr != "" || len(args) > 1 {
			return sp, out.Usage("give a command or --script FILE, not both")
		}
		if stdinFile != "" {
			return sp, out.Usage("--script sends the file as the script's input, so --stdin-file does not go with it; read other files inside the script")
		}
		var err error
		if sp.input, err = readFileOrStdin(cl, so.file); err != nil {
			return sp, localFileErr("FILE_NOT_FOUND", err, "")
		}
		if err := hiddenInInput(cl, so.file, sp.input); err != nil {
			return sp, err
		}
		noteApprovalScript(cl, scriptLabel("the script", so.file), sp.input)
		if err := guardBody(cl, string(sp.input)); err != nil {
			return sp, err
		}
		interpreter := cmp.Or(so.interpreter, shebangInterpreter(string(sp.input)))
		if win, err := targetWindows(cl, args[0]); err != nil || win {
			if err == nil {
				err = out.Usage("job start --script runs on Linux and other Unix servers; on Windows use `komando exec TARGET --script FILE`")
			}
			return sp, err
		}
		if readOnly {
			if sp.mutating, err = scriptReadOnly(cl, string(sp.input), interpreter, so.args, envs); err != nil {
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
		if sp.input, err = readFileOrStdin(cl, stdinFile); err != nil {
			return sp, localFileErr("FILE_NOT_FOUND", err, "check the --stdin-file path")
		}
		if err := hiddenInInput(cl, stdinFile, sp.input); err != nil {
			return sp, err
		}
		noteApprovalBody(cl, scriptLabel("the input", stdinFile), sp.input)
		// the input may be a script (bash -s): the policy reads it
		if err := guardBody(cl, string(sp.input)); err != nil {
			return sp, err
		}
	}
	sp.mutating, err = execReadOnly(cl, args[0], sp.command, sp.input, execOpts{stdinFile: stdinFile, env: envs}, readOnly)
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
func startJob(cl *call, ctx context.Context, c *sshx.Client, sp jobSpec) (started, error) {
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
		`export d; if command -v setsid >/dev/null 2>&1; then setsid nohup sh -c ` + sshx.Q(execsession.Wrapper(run, sp.timeout)) + ` sh "$u" > "$d/out.log" 2>&1 < /dev/null & ` +
		`else nohup sh -c ` + sshx.Q(execsession.Wrapper(run, sp.timeout)) + ` sh "$u" > "$d/out.log" 2>&1 < /dev/null & fi; echo $! > "$d/pid"; echo $!`
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
	if err := store.UpdateRuntime(cl.storeWrite(), func(s *store.State) error { s.Jobs[id] = j; return nil }); err != nil {
		return started{}, err
	}
	return started{ID: id, Host: c.Host.Name, PID: pid, OK: true}, nil
}

// jobRunner is what starts the job: the feed piped into sudo (as root, or
// --sudo-user) or sh, in the background, its pid in w. With the server's
// sudo password (pw, sent to the job as input), sudo is first asked
// whether it needs one: when it does not, the password is deleted unread,
// so it can never reach the command.
func jobRunner(c *sshx.Client, sp jobSpec, inner string) (start string, pw []byte, err error) {
	sh := "sh -c " + sshx.Q(inner)
	if !sp.sudo && sp.sudoUser == "" {
		return execsession.Feed(false) + " | " + sh + " & w=$!", nil, nil
	}
	user := ""
	if sp.sudoUser != "" {
		user = "-u " + sshx.Q(sp.sudoUser) + " "
	}
	if c.Host.SudoRef == "" {
		return execsession.Feed(false) + " | sudo -n " + user + sh + " & w=$!", nil, nil
	}
	p, err := vault.Resolve(c.Host.SudoRef)
	if err != nil {
		return "", nil, err
	}
	start = `if sudo -n ` + user + `sh -c : 2>/dev/null; then rm -f "$d/pw"; ` + execsession.Feed(false) + ` | sudo -n ` + user + sh +
		` & w=$!; else ` + execsession.Feed(true) + ` | sudo -S -p '' ` + user + sh + ` & w=$!; fi`
	return start, []byte(p + "\n"), nil
}

// sessionsOn turns exec's runs in a session on. It stays off until the
// v2.7 cut: exec then runs as before, and its session flags are hidden and
// refused.
var sessionsOn = false

// sessionOpts are exec's flags for a run in a session on the server.
type sessionOpts struct {
	attach []string
	offset int64
	wait   time.Duration
	logMax int64
	stop   bool
	signal string
	remove bool
}

// sessionFlags are exec's flags that come with sessions.
var sessionFlags = []string{"attach", "offset", "wait", "log-max", "stop", "signal", "remove"}

func (s *sessionOpts) bind(c *cobra.Command) {
	f := c.Flags()
	f.StringSliceVar(&s.attach, "attach", nil, "read the rest of these sessions on one server, and their exit codes")
	f.Int64Var(&s.offset, "offset", 0, "with --attach: start at this byte of the log (next_from of the last read)")
	durVar(f, &s.wait, "wait", time.Minute, "wait this long for the run to end; it goes on after (exit 7); 0 returns at once")
	s.logMax = 1 << 30
	f.Var(&bytesFlag{n: &s.logMax}, "log-max", "bytes of output the server keeps for the run, like 100MiB; more is dropped")
	f.BoolVar(&s.stop, "stop", false, "with --attach ID: stop the run, from the computer that started it")
	f.StringVar(&s.signal, "signal", "TERM", "with --stop: TERM, INT, HUP, QUIT or KILL")
	f.BoolVar(&s.remove, "remove", false, "with --attach ID: delete a finished session's folder on the server")
	if !sessionsOn {
		for _, n := range sessionFlags {
			_ = f.MarkHidden(n)
		}
	}
}

// refuseOff refuses the session flags while sessions are off.
func (s *sessionOpts) refuseOff(c *cobra.Command) error {
	if sessionsOn {
		return nil
	}
	for _, n := range sessionFlags {
		if c.Flags().Changed(n) {
			return out.Usage("--%s comes with exec sessions, which this build does not have yet", n)
		}
	}
	return nil
}

// wants says whether exec works on sessions that run already: --attach,
// or a flag that goes with it.
func (s *sessionOpts) wants(c *cobra.Command) bool {
	return len(s.attach) > 0 || slices.ContainsFunc([]string{"offset", "stop", "signal", "remove"}, c.Flags().Changed)
}

// attachCall is exec on sessions that run already: --attach IDs and no
// command (command says one was given); with --stop or --remove, one ID.
func (s *sessionOpts) attachCall(cl *call, ctx context.Context, c *cobra.Command, args []string, command bool) error {
	f := c.Flags()
	one := len(s.attach) == 1 && !f.Changed("offset") && !f.Changed("wait")
	switch {
	case len(s.attach) == 0:
		return out.Usage("--offset, --stop and --remove go with --attach ID")
	case command || len(args) > 1:
		return out.Usage("--attach works on sessions that run already: give no command with it")
	case f.Changed("signal") && !s.stop:
		return out.Usage("--signal goes with --stop")
	case s.stop && s.remove:
		return out.Usage("--stop and --remove go one at a time: stop the run, then remove it once it has ended")
	case (s.stop || s.remove) && !one:
		return out.Usage("--stop and --remove take one session ID, without --offset or --wait")
	case s.stop && !slices.Contains(execsession.Signals, s.signal):
		return out.Usage("--signal %q: give one of TERM, INT, HUP, QUIT or KILL", s.signal)
	case s.stop:
		return stopSession(cl, ctx, args[0], s.attach[0], s.signal, f.Changed("signal"))
	case s.remove:
		return removeSession(cl, ctx, args[0], s.attach[0])
	}
	return attachSessions(cl, ctx, args[0], *s)
}

// sessionRun is exec's run in a session folder on one server
// (execsession): it survives a dropped connection, and --attach reads it
// on. A nil sessionRun runs the command as before.
type sessionRun struct {
	opts     sessionOpts
	shown    string
	id       string // empty: no session (none could be made, or the start failed)
	nextFrom *int64 // where an --attach reads on, while the run goes on
}

// sessionFor is exec's session for this run, or nil: sessions are on, and
// the run is a plain exec on one server without --pty.
func sessionFor(name string, hosts []*store.Host, o execOpts, shown string) *sessionRun {
	if !sessionsOn || o.session == nil || name != "exec" || len(hosts) != 1 || o.pty {
		return nil
	}
	return &sessionRun{opts: *o.session, shown: shown}
}

// fill puts the session into a server's result: its ID (null when it ran
// without one) and, while it runs, next_from.
func (s *sessionRun) fill(hr *execHostResult) {
	if s == nil {
		return
	}
	hr.Session = json.RawMessage("null")
	if s.id != "" {
		hr.Session = json.RawMessage(strconv.Quote(s.id))
	}
	hr.NextFrom = s.nextFrom
}

// run starts r in a session on c and follows it. The first JSON line
// names the session. When no folder can be made there, r runs as before
// in a new call, which sends its input again.
func (s *sessionRun) run(cl *call, ctx context.Context, c *sshx.Client, r sshx.RunRequest) (*sshx.RunResult, error) {
	if s == nil {
		return sshx.Run(ctx, c, r)
	}
	host := c.Host.Name
	id, err := execsession.NewID()
	if err != nil {
		return nil, err
	}
	var facts execsession.Facts
	var warns []string
	if c.Host.Windows() {
		facts, err = s.beginWindows(cl, ctx, c, r, id)
	} else {
		facts, warns, err = s.beginUnix(cl, ctx, c, r, id)
	}
	if errors.Is(err, execsession.ErrNoFolder) {
		sessionLine(cl, nil, host)
		cl.out.Warn(host + ": no session folder can be made in the login user's home, so the command ran without a session: it ends if the connection drops")
		return sshx.Run(ctx, c, r)
	}
	if err != nil {
		return nil, err
	}
	for _, w := range warns {
		cl.out.Warn(host + ": " + w)
	}
	s.id = id
	rec := &store.ExecSession{ID: id, Host: host, Command: s.shown, PID: facts.PID, PGID: facts.PGID, ProcStart: facts.Start, Image: facts.Image, CmdLine: facts.CmdLine,
		StartedAt: time.Now().UTC(), Sudo: r.Sudo, SudoUser: r.SudoUser, Actor: actor(cl), Agent: cl.isAgent()}
	if err := store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error { st.ExecSessions[id] = rec; return nil }); err != nil {
		cl.out.Warn(host + ": session " + id + " runs, but this computer could not record it: " + err.Error())
	}
	sessionLine(cl, &id, host)
	return s.follow(cl, ctx, c, 0, s.opts.wait, r)
}

// beginUnix is the Unix start of a run: one call that sweeps old folders,
// makes this session's folder and starts the run, then the facts it
// printed. Whatever the sweep removed is forgotten here.
func (s *sessionRun) beginUnix(cl *call, ctx context.Context, c *sshx.Client, r sshx.RunRequest, id string) (execsession.Facts, []string, error) {
	host := c.Host.Name
	exports, err := sshx.EnvExports(c, r.Env)
	if err != nil {
		return execsession.Facts{}, nil, err
	}
	inner, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: r.Command, Dir: r.Dir, NoEnv: true})
	if err != nil {
		return execsession.Facts{}, nil, err
	}
	if exports != "" {
		inner = `eval "$(dd bs=1 count=` + strconv.Itoa(len(exports)) + ` 2>/dev/null)"; ` + inner
	}
	start, pw, err := jobRunner(c, jobSpec{sudo: r.Sudo, sudoUser: r.SudoUser}, inner)
	if err != nil {
		return execsession.Facts{}, nil, err
	}
	script, err := execsession.BeginScript(execsession.Start{ID: id, Shown: s.shown, Run: start, Env: len(exports),
		Password: len(pw), Input: r.Stdin != nil, Timeout: r.Timeout, LogMax: s.opts.logMax}, hostSessions(host))
	if err != nil {
		return execsession.Facts{}, nil, err
	}
	b, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Stdin: append(append([]byte(exports), pw...), r.Stdin...), Timeout: 30 * time.Second, MaxOutput: 64 << 10})
	if err != nil {
		return execsession.Facts{}, nil, err
	}
	forgetSessions(cl, host, execsession.Swept(b.Stdout, id))
	return execsession.ReadStart(host, b.ExitCode, b.Stdout, id)
}

// sessionLine names the session before any output: the first JSON line,
// or a line on stderr for a person.
func sessionLine(cl *call, id *string, host string) {
	if cl.out.Format != "text" {
		cl.out.Event(map[string]any{"session": id, "host": host})
	} else if id != nil {
		fmt.Fprintf(cl.out.Err, "Session %s on %s\n", *id, host)
	}
}

// follow reads session s.id on c from byte from until it ends or wait
// passes. r gives the output limit and the stream. A run read to its end
// is removed when the caller is the actor who started it.
func (s *sessionRun) follow(cl *call, ctx context.Context, c *sshx.Client, from int64, wait time.Duration, r sshx.RunRequest) (*sshx.RunResult, error) {
	t0 := time.Now()
	res := &sshx.RunResult{}
	var buf strings.Builder
	show := func(text string) {
		if r.Stream != nil {
			r.Stream("stdout", []byte(text))
		}
		if r.MaxOutput > 0 && buf.Len()+len(text) > r.MaxOutput {
			text, res.StdoutTruncated = text[:max(0, r.MaxOutput-buf.Len())], true
		}
		buf.WriteString(text)
	}
	read := func(ctx context.Context, script string) (string, int, error) {
		rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Timeout: 30 * time.Second, MaxOutput: readOutputMax(c.Host.Windows())})
		if err != nil {
			return "", 0, err
		}
		return rr.Stdout, rr.ExitCode, nil
	}
	f := execsession.Follow{Host: c.Host.Name, ID: s.id, Windows: c.Host.Windows(), From: from, Wait: wait, Every: time.Second,
		Lines: &execsession.Lines{Redact: cl.out.Redact, Agent: cl.isAgent()}, Show: show}
	done, err := f.Run(ctx, read)
	res.Stdout, res.DurationMS = buf.String(), time.Since(t0).Milliseconds()
	if err != nil {
		s.nextFrom = &done.NextFrom
		return res, err
	}
	st := done.Status
	switch {
	case st.Lost:
		res.ExitCode = -1
		cl.out.Warn(c.Host.Name + ": session " + s.id + " ended without an exit code: its process is gone (a reboot or out of memory)")
	case strings.HasPrefix(st.Killed, "TERM timeout"):
		res.ExitCode, res.TimedOut = -1, true
	case st.Killed != "":
		res.ExitCode, res.Signal = -1, strings.Fields(st.Killed)[0]
	default:
		res.ExitCode = st.Exit
	}
	if note := st.TruncatedNote(); note != "" {
		cl.out.Warn(c.Host.Name + ": " + note)
	}
	s.removeOwn(cl, ctx, c)
	return res, nil
}

// removeOwn removes a session read to its end, folder and record, when
// the caller is the actor who started it (A-C324-10): a reader that is
// someone else leaves it to the 7-day sweep.
func (s *sessionRun) removeOwn(cl *call, ctx context.Context, c *sshx.Client) {
	rt, err := store.ReadRuntime()
	if err != nil {
		return
	}
	rec := rt.ExecSessions[s.id]
	if rec == nil || rec.Host != c.Host.Name || !ownRun(cl, rec) {
		return
	}
	script, err := removeScriptFor(c.Host, s.id, rec)
	if err != nil {
		return
	}
	rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: script, Timeout: 30 * time.Second, MaxOutput: 4 << 10})
	if err != nil || rr.ExitCode != 0 {
		cl.out.Warn(c.Host.Name + ": session " + s.id + " was read to its end but is still on the server; the sweep of a later exec removes it after 7 days")
		return
	}
	forgetSessions(cl, c.Host.Name, []string{s.id})
}

// hostSessions are the records of host's sessions on this computer.
func hostSessions(host string) []*store.ExecSession {
	rt, err := store.ReadRuntime()
	if err != nil {
		return nil
	}
	var recs []*store.ExecSession
	for _, rec := range rt.ExecSessions {
		if rec.Host == host {
			recs = append(recs, rec)
		}
	}
	return recs
}

// forgetSessions drops the records of host's sessions ids.
func forgetSessions(cl *call, host string, ids []string) {
	if len(ids) == 0 {
		return
	}
	err := store.UpdateRuntime(cl.storeWrite(), func(st *store.State) error {
		for _, id := range ids {
			if rec := st.ExecSessions[id]; rec != nil && rec.Host == host {
				delete(st.ExecSessions, id)
			}
		}
		return nil
	})
	if err != nil {
		cl.out.Warn("could not drop the records of removed sessions: " + err.Error())
	}
}

// attachSessions is exec --attach: it reads on the sessions ids on the one
// server target names, from --offset (one ID only), and waits for all of
// them together up to --wait. A read only reads: it runs komando's own
// read script with checked IDs, and sweeps nothing.
func attachSessions(cl *call, ctx context.Context, target string, so sessionOpts) error {
	for _, id := range so.attach {
		if err := execsession.CheckID(id); err != nil {
			return err
		}
	}
	if so.offset < 0 || (so.offset > 0 && len(so.attach) > 1) {
		return out.Usage("--offset goes with one session ID, and is 0 or more")
	}
	st, h, err := sessionHost(cl, target)
	if err != nil {
		return err
	}
	hosts := []*store.Host{h}
	deadline := time.Now().Add(so.wait)
	res := fanout(cl, ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		var rs []execHostResult
		for _, id := range so.attach {
			s := &sessionRun{opts: so, id: id}
			rr, err := s.follow(cl, ctx, c, so.offset, max(0, time.Until(deadline)), sshx.RunRequest{MaxOutput: maxOutput(cl, st)})
			hr := execHostResult{Host: c.Host.Name, RunResult: rr, Error: errOrNil(err)}
			s.fill(&hr)
			hr.OK = err == nil && rr.ExitCode == 0 && !rr.TimedOut
			rs = append(rs, hr)
		}
		return rs, nil
	})[0]
	shown := shellLine(append([]string{"--attach"}, so.attach...))
	if res.Err != nil {
		audit(cl, st, "exec", hostNames(hosts), shown, false, map[string]any{"attach": so.attach})
		return res.Err
	}
	data := execData{Command: shown, Results: res.Value.([]execHostResult)}
	worst := 0
	var fails []hostFail
	for _, hr := range data.Results {
		switch {
		case hr.OK:
			data.Summary.OK++
			continue
		case hr.Error != nil:
			worst = worse(worst, hr.Error.Exit)
			fails = append(fails, hostFail{host: hr.Host, reason: failReason(0, hr.Error), err: hr.Error})
		default:
			worst = worse(worst, out.ExitRemote)
			fails = append(fails, hostFail{host: hr.Host, reason: fmt.Sprintf("exit %d", hr.ExitCode)})
		}
		data.Summary.Failed++
		data.Summary.FailedHosts = append(data.Summary.FailedHosts, hr.Host)
	}
	data.Summary.Total = len(data.Results)
	audit(cl, st, "exec", hostNames(hosts), shown, data.Summary.Failed == 0, map[string]any{"attach": so.attach, "exit_codes": exitCodes(data.Results)})
	return finishFleet(cl, "exec", data, data.Summary, worst, fails)
}

// sessionHost is the one server target names, for --attach
// and its --stop and --remove.
func sessionHost(cl *call, target string) (*store.State, *store.Host, error) {
	st, err := loadState()
	if err != nil {
		return nil, nil, err
	}
	hosts, err := resolveTargets(cl, st, target)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) != 1 {
		return nil, nil, out.Usage("--attach works on sessions on one server: name that server, as the exec that started them did")
	}
	return st, hosts[0], nil
}

// readRuntime is this computer's runtime data; none yet reads as empty.
func readRuntime() (*store.Runtime, error) {
	rt, err := store.ReadRuntime()
	if errors.Is(err, fs.ErrNotExist) {
		return &store.Runtime{}, nil
	}
	return rt, err
}

// sessionChange is the result of --stop or --remove.
type sessionChange struct {
	Session   string `json:"session"`
	Host      string `json:"host"`
	Signal    string `json:"signal,omitempty"`
	Signalled string `json:"signalled,omitempty"` // group | pid: what the signal went to
	PID       int    `json:"pid,omitempty"`
	Removed   bool   `json:"removed,omitempty"`
}

func (s sessionChange) Text() string {
	if s.Removed {
		return "removed session " + s.Session + " on " + s.Host
	}
	return "sent " + s.Signal + " to the " + cmp.Or(s.Signalled, "process") + " of session " + s.Session + " on " + s.Host + " (pid " + strconv.Itoa(s.PID) + ")"
}

// changeSession runs script, a --stop or --remove of session id on h: a
// change, guarded as job kill is (a protected server asks first), and
// recorded in the audit log as shown with extra. input gives what the
// script reads, after the guard. A dry run prints the script and returns
// nil, nil.
func changeSession(cl *call, ctx context.Context, st *store.State, h *store.Host, rec *store.ExecSession, id, shown, script string, input func() ([]byte, error), extra map[string]any) (*sshx.RunResult, error) {
	extra["attach"] = []string{id}
	// the starter's window comes first and names the protected server too,
	// so the protected change's check never answers for a starter it did
	// not show
	err := guardOtherStarter(cl, st, h, rec)
	if err == nil {
		err = Guard(cl, st, []*store.Host{h}, "", true)
	}
	if err != nil {
		extra["blocked"] = toErr(err).Code
		audit(cl, st, "exec", []string{h.Name}, shown, false, extra)
		return nil, err
	}
	if cl.flags.dryRun {
		cl.out.Print("exec", map[string]any{"session": id, "host": h.Name, "would_run": script}, nil)
		return nil, nil
	}
	var stdin []byte
	if input != nil {
		if stdin, err = input(); err != nil {
			return nil, err
		}
	}
	var r *sshx.RunResult
	err = withClient(cl, ctx, st, h, func(c *sshx.Client) error {
		var err error
		r, err = sshx.Run(ctx, c, sshx.RunRequest{Command: script, Stdin: stdin, Timeout: 30 * time.Second, MaxOutput: 4 << 10})
		return err
	})
	audit(cl, st, "exec", []string{h.Name}, shown, err == nil && r.ExitCode == 0, extra)
	return r, err
}

// guardOtherStarter: an AI agent that stops or removes a run another
// actor started (a person, a script, or another agent) asks the person
// in the window first, as guardSafety does. Its own runs, a
// caller that is not an agent, and a removal without a record (no starter
// known) stay at the change tier. On a protected server the one window
// names the protection too, as Guard would, so Guard's --yes check that
// follows is the same question already answered.
func guardOtherStarter(cl *call, st *store.State, h *store.Host, rec *store.ExecSession) error {
	if rec == nil || !cl.isAgent() || ownRun(cl, rec) {
		return nil
	}
	starter := rec.Actor + " at a terminal or in a script"
	if rec.Agent {
		starter = rec.Actor + "'s AI agent"
	}
	why := fmt.Sprintf("session %s on %s was started by %s, not by this AI agent", rec.ID, rec.Host, starter)
	reasons := []string{why}
	if protectedHost(st, h) {
		reasons = append(reasons, protWhy([]string{h.Name}), targetsWhy(st, []*store.Host{h}))
	}
	if cl.yesOK(reasons...) {
		return nil
	}
	return cl.policyStop(approvalErr(cl, "CONFIRM_REQUIRED", why))
}

// ownRun says whether the caller is the actor who started run rec: the
// same name, and an agent or not alike.
func ownRun(cl *call, rec *store.ExecSession) bool {
	return rec.Actor == actor(cl) && rec.Agent == cl.isAgent()
}

// stopSession is exec --attach ID --stop: it signals the run from its
// record on this computer alone (A-C324-1), through sudo as the run ran
// (A-C324-2), and keeps the record: the removal drops it.
func stopSession(cl *call, ctx context.Context, target, id, sig string) error {
	st, h, err := sessionHost(cl, target)
	if err != nil {
		return err
	}
	rt, err := readRuntime()
	if err != nil {
		return err
	}
	rec, err := execsession.ForStop(rt, h.Name, id)
	if err != nil {
		return err
	}
	password := (rec.Sudo || rec.SudoUser != "") && h.SudoRef != ""
	script, err := execsession.StopCommand(rec, sig, password)
	if err != nil {
		return err
	}
	var input func() ([]byte, error)
	if password {
		input = func() ([]byte, error) {
			p, err := vault.Resolve(h.SudoRef)
			return []byte(p + "\n"), err
		}
	}
	shown := shellLine([]string{"--attach", id, "--stop", "--signal", sig})
	r, err := changeSession(cl, ctx, st, h, rec, id, shown, script, input, map[string]any{"stop": sig, "pid": rec.PID})
	if err != nil || r == nil {
		return err
	}
	if err := execsession.StopExit(h.Name, id, r.ExitCode, r.Stderr); err != nil {
		return err
	}
	cl.out.Print("exec", sessionChange{Session: id, Host: h.Name, Signal: sig, Signalled: execsession.Signalled(r.Stdout), PID: rec.PID}, nil)
	return nil
}

// removeSession is exec --attach ID --remove: it deletes a finished
// session's folder and drops its record. With this computer's record the
// stored process decides that the run ended; without one, the files on
// the server.
func removeSession(cl *call, ctx context.Context, target, id string) error {
	st, h, err := sessionHost(cl, target)
	if err != nil {
		return err
	}
	rt, err := readRuntime()
	if err != nil {
		return err
	}
	rec := rt.ExecSessions[id]
	if rec != nil && rec.Host != h.Name {
		rec = nil
	}
	script, err := execsession.RemoveScript(id, rec)
	if err != nil {
		return err
	}
	r, err := changeSession(cl, ctx, st, h, rec, id, shellLine([]string{"--attach", id, "--remove"}), script, nil, map[string]any{"remove": true})
	if err != nil || r == nil {
		return err
	}
	if err := execsession.RemoveExit(h.Name, id, r.ExitCode); err != nil {
		return err
	}
	forgetSessions(cl, h.Name, []string{id})
	cl.out.Print("exec", sessionChange{Session: id, Host: h.Name, Removed: true}, nil)
	return nil
}

// errOrNil is err as a result's error, or nil.
func errOrNil(err error) *out.Error {
	if err == nil {
		return nil
	}
	return toErr(err)
}
