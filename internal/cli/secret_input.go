package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
)

// An AI agent sees every vault value as [credential:NAME]. That masking would
// tell it which of its guesses is a secret: `credential password show GUESS` or `exec
// web1 -- echo GUESS` print [credential:NAME] on a hit; and refusing such
// input would tell it the same. So an agent's arguments, script or input
// that hold a vault value get the answer any other value gets: the value
// it typed is not hidden in that command's output (Printer.Spare), which
// shows it nothing it did not type. The audit log records it, where a
// person sees the guessing; the record never says which secret matched.

// noteSecretInput records that what holds a vault value, and stops hiding
// the values in s in this command's output.
func noteSecretInput(cl *call, cmd *cobra.Command, what, s string) {
	name := "komando"
	if cmd != nil {
		name = commandName(cmd)
	}
	audit(cl, nil, name, nil, "", true, map[string]any{"secret_value_in_input": what})
	cl.out.Spare(s)
}

// secretInArgs notes an agent's command line that holds a vault value:
// its arguments (the remote command after -- too) and the flags it gave.
func secretInArgs(cmd *cobra.Command, args []string) {
	cl := callOf(cmd)
	if !cl.isAgent() || cl.out.Secrets == nil {
		return
	}
	words := append([]string{}, args...)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			words = append(words, sv.GetSlice()...)
			return
		}
		words = append(words, f.Value.String())
	})
	if s := strings.Join(words, "\x00"); cl.out.HoldsVaultValue(s) {
		noteSecretInput(cl, cmd, "the arguments", s)
	}
}

// secretInBody notes an agent's script, --stdin-file or SQL file that
// holds a vault value.
func secretInBody(cl *call, what string, b []byte) {
	if cl.isAgent() && len(b) <= hiddenScanMax && cl.out.Secrets != nil && cl.out.HoldsVaultValue(string(b)) {
		noteSecretInput(cl, nil, what, string(b))
	}
}

// secretValueLeaves are the commands whose one argument names a secret and
// that read its value from input (typed hidden, --from-env or a pipe).
var secretValueLeaves = map[string]bool{"credential.password.add": true, "credential.token.add": true, "secret.check": true}

// secretValueInArgs refuses a value typed after the secret's name on a
// secretValueLeaves command, before the arguments are counted, so the
// person learns why: it would stay in shell history and in ps.
func secretValueInArgs(id string, args []string) error {
	if !secretValueLeaves[id] || len(args) < 2 {
		return nil
	}
	const why = "refusing a secret value on the command line: it would be saved in shell history"
	words := strings.ReplaceAll(id, ".", " ")
	if id != "secret.check" {
		return out.Errf(out.ExitUsage, "SECRET_IN_ARGS", "run `komando "+words+" "+args[0]+"` and type it (hidden), use --from-env VAR, or pipe it in (stdin)", why)
	}
	return out.Errf(out.ExitUsage, "SECRET_IN_ARGS", "run `komando "+words+" "+args[0]+"` and type it (hidden), or pipe it in (stdin)", why)
}

// hideBeforeStart is the pre-run's hiding for an error that comes before it
// (an argument or flag error, a typo under a group), whose answer may repeat
// what was typed: the stored values for all, and the mask for an AI agent.
func hideBeforeStart(cl *call, cmd *cobra.Command) {
	if cmd != nil && leavesHomeNow(cmd) {
		return // its output holds no secrets, and the vault is in ~/.komando
	}
	cl.out.SetSecrets(vaultValues)
	cl.out.Mask = cl.io.Caller().IsAgent()
}
