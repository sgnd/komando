package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/tmpclean"
	"github.com/sgnd/komando/internal/vault"
)

func runCmd() *cobra.Command {
	var env []string
	c := &cobra.Command{
		Use:   "run -- COMMAND [ARGS...]",
		Short: "Run a local command with vault secrets in its environment",
		Long: `Starts COMMAND on this computer with the --env values in its environment.
A value secret:NAME is read from the vault right before the program starts,
so it is never in the command line or the shell history. The program starts
directly, without a shell, with your environment minus komando's own
KOMANDO_* variables and the values that unlock the vault. For an AI agent
with secrets, --env may add variables but never replace one komando sets
(HOME, PATH, USER, LANG, ...), and may not set what decides which code or
settings the program loads: LD_PRELOAD, DYLD_*, NODE_OPTIONS, PYTHON*,
BASH_ENV, a pager, an editor, an askpass helper, an rc file, a proxy,
GIT_*, SSH_*, XDG_*, a tool's config file (KUBECONFIG, DOCKER_CONFIG,
*_CONFIG_FILE, AWS_*_FILE, NPM_CONFIG_*) or a toolchain's (CC, CXX, GOFLAGS,
GOTOOLCHAIN, CARGO_*, RUSTC_WRAPPER, JAVA_HOME, MAVEN_OPTS). The program gets HOME, USER and LOGNAME from your
OS account (USERPROFILE on Windows), LANG, LC_*, TERM, TMPDIR, TZ, the
Windows system folders, a system PATH and its --env values.

The program's output goes through komando's masking: a vault value it
prints shows as [secret:NAME]. komando exits with the program's exit code.

For an AI agent every secret:NAME needs a person's yes (--yes, then
komando's window names the secrets and the program), since the program
could print a value in a form masking does not know. A secret a protected
server, conn or VPN uses asks a person at a terminal too.`,
		Example: `  komando secret run --env PGPASSWORD=secret:db-main -- psql -h 10.0.0.5 -U app
  komando secret run -e AWS_SECRET_ACCESS_KEY=secret:aws-ci -e AWS_REGION=eu-west-1 -- terraform plan
  komando secret run --dry-run --env TOKEN=secret:gh-token -- ./deploy.sh`,
		Args: cobra.MinimumNArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return runLocal(cl, env, args)
		}),
	}
	c.Flags().StringArrayVarP(&env, "env", "e", nil, "put KEY=VALUE or KEY=secret:NAME in the program's environment (repeatable)")
	return c
}

func runLocal(cl *call, pairs, args []string) error {
	for _, a := range args[1:] {
		if argHasRef(a) {
			return out.Usage("a secret reference goes in --env KEY=secret:NAME, not in the program's arguments (%q)", a)
		}
	}
	env, err := parseEnv(pairs)
	if err != nil {
		return err
	}
	refs := envSecretRefs(env)
	if err := reservedRefs(refs); err != nil {
		return err
	}
	agentSecrets := cl.isAgent() && len(refs) > 0
	if agentSecrets {
		for _, k := range slices.Sorted(maps.Keys(env)) {
			if loadsCode(k) || baseSets(k) {
				return out.Usage("an AI agent's run with secrets may not set %s: it decides which code or settings the program loads, which could read the values", k)
			}
		}
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	prog, err := localTool(cl, args[0], nil)
	if err != nil {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "check the name, or give the program's path", "%s is not a program on this computer: %v", args[0], err)
	}
	if real, err := filepath.EvalSymlinks(prog); err == nil {
		prog = real
	}
	before, err := os.Stat(prog)
	if err != nil {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "check the name, or give the program's path", "%s is not a program on this computer: %v", args[0], err)
	}
	keys := slices.Sorted(maps.Keys(env))
	rec := map[string]any{"program": prog, "env": keys, "secrets": refs}
	shown := strings.Join(append([]string{prog}, args[1:]...), " ")

	if err := runGuard(cl, st, refs, prog, plainPairs(env)); err != nil {
		if !cl.flags.dryRun {
			audit(cl, st, "secret run", nil, shown, false, withBlocked(rec, err))
		}
		return err
	}
	if cl.flags.dryRun {
		envShown := map[string]string{}
		for _, k := range keys {
			envShown[k] = env[k]
			if !strings.HasPrefix(env[k], "secret:") {
				envShown[k] = "[value]"
			}
		}
		cl.out.Print("secret run", map[string]any{"program": prog, "args": args[1:], "env": envShown, "dry_run": true}, nil)
		return nil
	}

	vals := make([]string, 0, len(keys))
	for _, k := range keys {
		v := env[k]
		if strings.HasPrefix(v, "secret:") {
			if v, err = vault.Resolve(v); err != nil {
				return out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", "see them with `komando secret list`", "%s for %s: %v", env[k], k, err)
			}
		}
		vals = append(vals, k+"="+v)
	}
	if after, err := os.Stat(prog); err != nil || !sameFile(before, after) {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "run it again", "%s changed after komando checked it; it did not run", prog)
	}
	audit(cl, st, "secret run", nil, shown, true, rec)

	c := exec.Command(prog, args[1:]...)
	c.Args[0] = args[0]
	base := withoutKomandoEnv(cl.environ(), keys)
	if agentSecrets {
		var cleanup func()
		base, cleanup = agentBaseEnv(cl, base)
		defer cleanup()
	}
	c.Env = append(base, vals...)
	done, err := pinProgram(c, before)
	if err != nil {
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "run it again", "%s changed after komando checked it; it did not run", prog)
	}
	defer done()
	return startMasked(cl, c, prog)
}

// startMasked runs c to the end with its output through the masker, and
// returns the program's exit code as komando's.
func startMasked(cl *call, c *exec.Cmd, prog string) error {
	c.Stdin = cl.stdin
	// A child the program leaves in the background can keep its output
	// open; komando stops reading this long after the program exits.
	c.WaitDelay = outputWait
	endWithKomando(c)
	var wg sync.WaitGroup
	var mu sync.Mutex
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	c.Stdout, c.Stderr = stdoutW, stderrW
	for r, w := range map[*io.PipeReader]io.Writer{stdoutR: cl.out.W, stderrR: cl.out.Err} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			maskCopy(cl, &mu, w, r)
		}()
	}
	started, stop := forwardSignals()
	err := c.Start()
	if err == nil {
		forget := runningPrograms.add(c.Process)
		started <- c.Process
		err = c.Wait()
		forget()
	}
	stop()
	stdoutW.Close()
	stderrW.Close()
	wg.Wait()
	var ee *exec.ExitError
	switch {
	case errors.Is(err, exec.ErrWaitDelay): // the program exited 0
		return nil
	case errors.As(err, &ee):
		if code := ee.ExitCode(); code > 0 {
			return exitCode(code)
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return exitCode(128 + int(ws.Signal())) // as a shell reports it
		}
		return exitCode(out.ExitError)
	case err != nil:
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "check that the program runs on this computer", "%s did not start: %v", prog, err)
	}
	return nil
}

// outputWait is how long secret run reads a program's output after the
// program exits; a background child that holds it longer is cut off.
var outputWait = 3 * time.Second

// forwardSignals passes a SIGTERM or SIGHUP komando gets on to the
// program, so it does not run on with the secrets after komando is
// stopped. A Ctrl-C at the terminal already reaches the program itself (it
// is in the same process group); sending it again would count as a second
// Ctrl-C, which many programs (terraform) take as "stop now". Signals are
// caught from before the start, and passed on once the program runs.
// Windows cannot pass a signal on, so there the program is ended.
func forwardSignals() (started chan<- *os.Process, stop func()) {
	ch := make(chan os.Signal, 2)
	for _, sig := range forwardedSignals {
		if !signal.Ignored(sig) { // nohup: a closed terminal does not stop the program
			signal.Notify(ch, sig)
		}
	}
	start := make(chan *os.Process, 1)
	done := make(chan struct{})
	go func() {
		var p *os.Process
		var held []os.Signal
		for {
			select {
			case p = <-start:
				for _, s := range held {
					passSignal(p, s)
				}
			case s := <-ch:
				if p == nil {
					held = append(held, s)
				} else {
					passSignal(p, s)
				}
			case <-done:
				return
			}
		}
	}()
	return start, func() {
		signal.Stop(ch)
		close(done)
	}
}

func passSignal(p *os.Process, s os.Signal) {
	if runtime.GOOS == "windows" {
		p.Kill()
	} else {
		p.Signal(s)
	}
}

// argHasRef reports whether a program argument holds a secret reference
// of any form komando resolves (secret:, env:, vault:, op://, ...), as the
// whole argument or after an = (--password=env:PW).
func argHasRef(a string) bool {
	if strings.Contains(a, "secret:") {
		return true
	}
	for _, r := range vault.Refs {
		p, _, _ := strings.Cut(r, " ")
		if i := strings.Index(p, "://"); i >= 0 {
			p = p[:i+3]
		} else {
			p = p[:strings.IndexByte(p, ':')+1]
		}
		if p == "file:" && strings.Contains(a, "file://") {
			continue // a file:// URL, not a reference
		}
		if strings.HasPrefix(a, p) || strings.Contains(a, "="+p) {
			return true
		}
	}
	return false
}

// runGuard is run's approval: an AI agent needs a person's yes for every
// secret, and a secret a protected entry uses needs one from anybody.
func runGuard(cl *call, st *store.State, refs []string, prog string, plain []string) error {
	if len(refs) == 0 {
		return nil
	}
	var prot []string
	for _, r := range refs {
		prot = append(prot, protectedUsers(st, secretUsers(st, strings.TrimPrefix(r, "secret:")))...)
	}
	if prot = dedupe(prot); len(prot) > 0 && !cl.yesOK() && !confirmProtected(cl, prot) {
		if err := cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
			fmt.Sprintf("%s used by protected %s would go to %s on this computer", strings.Join(refs, ", "), strings.Join(prot, ", "), prog))); err != nil {
			return err
		}
	}
	where := "the program " + prog + " on this computer"
	if !toolSafe(cl, prog) {
		where += " (a program any program of yours can replace)"
	}
	if len(plain) > 0 {
		where += ", with " + strings.Join(plain, " ") + " also set"
	}
	return guardSecretUse(cl, refs, where)
}

// plainPairs are the --env pairs whose value is not a secret reference, as
// KEY=VALUE; the approval window shows them, since they shape what the
// program does.
func plainPairs(env map[string]string) []string {
	var pairs []string
	for _, k := range slices.Sorted(maps.Keys(env)) {
		if !strings.HasPrefix(env[k], "secret:") {
			pairs = append(pairs, k+"="+env[k])
		}
	}
	return pairs
}

// agentKeep are the variables an AI agent's run with secrets keeps from the
// environment. Anything else (a pager, an editor, an askpass helper, a
// proxy, a startup file) could hand the values to a program the agent
// chose, so the program gets only these, its --env values, a fixed system
// PATH, and HOME and the user name from the OS account: a HOME the agent
// picked could hold a .psqlrc, .gitconfig or .npmrc that runs its code.
var agentKeep = []string{"LANG", "TERM", "TMPDIR", "TZ", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}

// accountKeys are what agentBaseEnv sets itself, from the OS account.
var accountKeys = []string{"PATH", "HOME", "USER", "LOGNAME", "USERPROFILE"}

// baseSets reports whether agentBaseEnv sets k (any case): from the
// account, or kept from the environment. An agent's plain --env may add
// keys, never replace one of these.
func baseSets(k string) bool {
	k = strings.ToUpper(k)
	return slices.Contains(accountKeys, k) || slices.Contains(agentKeep, k) || strings.HasPrefix(k, "LC_")
}

func agentBaseEnv(cl *call, env []string) ([]string, func()) {
	kept := []string{"PATH=" + systemPath}
	cleanup := func() {}
	if u, err := user.Current(); err == nil {
		name := u.Username
		if _, after, ok := strings.Cut(name, `\`); ok {
			name = after // DOMAIN\name on Windows
		}
		home := u.HomeDir
		if runtime.GOOS == "linux" && home == os.Getenv("HOME") && !inPasswd(passwdPath, u.Uid) {
			home, cleanup = freshHome(cl)
		}
		kept = append(kept, "HOME="+home, "USER="+name, "LOGNAME="+name)
		if runtime.GOOS == "windows" {
			kept = append(kept, "USERPROFILE="+home)
		}
	}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if baseSets(k) && !slices.Contains(accountKeys, strings.ToUpper(k)) {
			kept = append(kept, kv)
		}
	}
	return kept, cleanup
}

// passwdPath is the account list a Linux build reads; tests change it.
var passwdPath = "/etc/passwd"

// inPasswd reports whether uid has a line in the passwd file at path. A
// build without cgo finds no account that only NSS (LDAP, sssd) knows, and
// user.Current then takes HOME from the environment, which the agent sets.
func inPasswd(path, uid string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for line := range strings.Lines(string(b)) {
		if f := strings.Split(line, ":"); len(f) > 2 && f[2] == uid {
			return true
		}
	}
	return false
}

// freshHome makes an empty HOME for the program, removed by the returned
// func: komando could not read the account's own HOME.
func freshHome(cl *call) (string, func()) {
	dir, err := os.MkdirTemp("", "komando-home-")
	if err != nil {
		fmt.Fprintf(cl.out.Stderr(), "komando: your account is not in %s and no empty HOME could be made (%v), so the program gets HOME=%s\n", passwdPath, err, os.DevNull)
		return os.DevNull, func() {}
	}
	forget := tmpclean.Add(dir)
	fmt.Fprintf(cl.out.Stderr(), "komando: your account is not in %s, so the program gets an empty HOME (%s), not the one in your environment\n", passwdPath, dir)
	return dir, func() {
		os.RemoveAll(dir)
		forget()
	}
}

// loadsCode reports whether an environment variable makes a program, its
// runtime or its shell load or run code it names: a library, a startup or
// rc file, an interpreter option, a pager, an editor, an askpass helper, a
// proxy, git's and ssh's settings, a tool's config file (kubectl, docker,
// aws, pip), or a toolchain's compiler or home. Code reached that way
// could read the injected values and write them where masking never sees
// them.
func loadsCode(k string) bool {
	k = strings.ToUpper(k)
	for _, p := range []string{"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY", "NODE_", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "GIT_", "SSH_", "XDG_", "NPM_CONFIG_", "CARGO_"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	for _, sfx := range []string{"PAGER", "RC", "_PROXY"} { // PSQL_PAGER, PSQLRC, INPUTRC, https_proxy
		if strings.HasSuffix(k, sfx) {
			return true
		}
	}
	for _, sfx := range []string{"_CONFIG_FILE", "KUBECONFIG", "DOCKER_CONFIG"} { // PIP_CONFIG_FILE
		if strings.HasSuffix(k, sfx) {
			return true
		}
	}
	if strings.HasPrefix(k, "AWS_") && strings.HasSuffix(k, "_FILE") { // AWS_SHARED_CREDENTIALS_FILE
		return true
	}
	switch k {
	case "GOFLAGS", "GOTOOLCHAIN", "GOENV", "RUSTC", "RUSTC_WRAPPER", "JAVA_HOME", "MAVEN_OPTS", "GRADLE_OPTS", "CC", "CXX", // pick the toolchain's binaries
		"BASH_ENV", "ENV", "ZDOTDIR", "PROMPT_COMMAND", "SHELLOPTS", "IFS", "EDITOR", "VISUAL",
		"BROWSER", "LESSOPEN", "LESSCLOSE", "SHELL":
		return true
	}
	return strings.Contains(k, "ASKPASS")
}

// sameFile reports whether the program file is the one komando checked.
func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

func withBlocked(rec map[string]any, err error) map[string]any {
	rec = maps.Clone(rec)
	rec["blocked"] = toErr(err).Code
	return rec
}

// withoutKomandoEnv drops komando's own KOMANDO_* variables and the keys
// run sets itself from env.
func withoutKomandoEnv(env, set []string) []string {
	kept := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, "KOMANDO_") && !slices.Contains(set, k) {
			kept = append(kept, kv)
		}
	}
	return kept
}

// maskCopy copies the program's output to w by whole lines, through the
// masker, so a value split across two reads is still hidden.
func maskCopy(cl *call, mu *sync.Mutex, w io.Writer, r io.Reader) {
	lb := lineBuffer{mask: cl.out}
	buf := make([]byte, 32<<10)
	show := func(s string) {
		if s == "" || w == nil {
			return
		}
		mu.Lock()
		fmt.Fprint(w, cl.out.Redact(s))
		mu.Unlock()
	}
	for {
		n, err := r.Read(buf)
		if n > 0 {
			show(lb.add(buf[:n]))
		}
		if err != nil {
			break
		}
	}
	show(lb.flush())
}

// runningPrograms are the programs secret run started that still run. A second
// Ctrl-C ends komando at once (hardStop); it ends these first, so none
// runs on with the secrets, unmasked, in a HOME komando removes.
var runningPrograms procSet

type procSet struct {
	mu    sync.Mutex
	procs map[*os.Process]bool
}

func (s *procSet) add(p *os.Process) (forget func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.procs == nil {
		s.procs = map[*os.Process]bool{}
	}
	s.procs[p] = true
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.procs, p)
	}
}

// killAll ends every running program (SIGKILL: it cannot be caught).
func (s *procSet) killAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p := range s.procs {
		p.Kill()
	}
}
