package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// An AI agent sees every vault value as [secret:NAME]. That masking would
// tell it which of its guesses is a secret: `secret get GUESS` or `exec
// web1 -- echo GUESS` print [secret:NAME] on a hit; and refusing such
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
