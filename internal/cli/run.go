package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
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
with secrets, variables that make a program load other code (LD_PRELOAD,
DYLD_*, NODE_OPTIONS, PYTHON*, BASH_ENV and the like) are refused in --env
and dropped from the environment.

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
		if strings.Contains(a, "secret:") {
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
			if loadsCode(k) {
				return out.Usage("an AI agent's run with secrets may not set %s: it makes the program load other code, which could read the values", k)
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

	if err := runGuard(cl, st, refs, prog, plainKeys(env)); err != nil {
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
		base = slices.DeleteFunc(base, func(kv string) bool {
			k, _, _ := strings.Cut(kv, "=")
			return loadsCode(k)
		})
	}
	c.Env = append(base, vals...)
	c.Stdin = cl.stdin
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
	err = c.Start()
	if err == nil {
		err = c.Wait()
	}
	stdoutW.Close()
	stderrW.Close()
	wg.Wait()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		if code := ee.ExitCode(); code > 0 {
			return exitCode(code)
		}
		return exitCode(out.ExitError) // ended by a signal
	case err != nil:
		return out.Errf(out.ExitNotFound, "TOOL_MISSING", "check that the program runs on this computer", "%s did not start: %v", prog, err)
	}
	return nil
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
		where += ", with " + strings.Join(plain, ", ") + " also set"
	}
	return guardSecretUse(cl, refs, where)
}

// plainKeys are the --env keys whose value is not a secret reference; the
// approval window names them, since they shape what the program does.
func plainKeys(env map[string]string) []string {
	var keys []string
	for _, k := range slices.Sorted(maps.Keys(env)) {
		if !strings.HasPrefix(env[k], "secret:") {
			keys = append(keys, k)
		}
	}
	return keys
}

// loadsCode reports whether an environment variable makes a program, its
// runtime or its shell load code it names (a library, a startup file, an
// interpreter option). Code loaded that way could read the injected values
// and write them where masking never sees them.
func loadsCode(k string) bool {
	k = strings.ToUpper(k)
	for _, p := range []string{"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY", "NODE_", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "GIT_SSH", "GIT_EXEC_PATH", "GIT_CONFIG"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return k == "BASH_ENV" || k == "ENV" || k == "ZDOTDIR" || k == "PROMPT_COMMAND" || k == "SHELLOPTS" || k == "IFS"
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
	var lb lineBuffer
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
