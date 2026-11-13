package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
)

// An AI agent sees every vault value as [secret:NAME]. That masking would
// tell it which of its guesses is a secret: `secret get GUESS` or `exec
// web1 -- echo GUESS` print [secret:NAME] on a hit. So komando refuses an
// agent's arguments, script or input that hold a vault value, before
// anything runs (a dry run too: its output would mask the same way), and
// writes the refusal to the audit log, where a person sees the guessing.
// The message never says which secret matched. A value the agent got
// back from a server in another form (decoded there) cannot be caught.

// secretInputErr is the refusal; what says what held the value ("the
// arguments hold", "FILE holds").
func secretInputErr(cmd *cobra.Command, what string) error {
	e := out.Errf(out.ExitUsage, "SECRET_INPUT_INVALID",
		"never type a secret's value: put {{secret:NAME}} where komando takes it (fs write, fs replace, -e), or ask the user to keep the value with `komando secret set NAME` and use that name",
		"%s the value of a secret in komando's vault; an AI agent never sends one (this was written to the audit log)", what)
	name := "komando"
	if cmd != nil {
		name = commandName(cmd)
	}
	audit(nil, name, nil, "", false, map[string]any{"blocked": e.Code, "message": e.Message})
	return e
}

// secretInArgs refuses an agent's command line that holds a vault value:
// its arguments (the remote command after -- too) and the flags it gave.
func secretInArgs(cmd *cobra.Command, args []string) error {
	if !isAgent() || out.P.Secrets == nil {
		return nil
	}
	words := append([]string{}, args...)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			words = append(words, sv.GetSlice()...)
			return
		}
		words = append(words, f.Value.String())
	})
	if !out.P.HoldsVaultValue(strings.Join(words, "\x00")) {
		return nil
	}
	return secretInputErr(cmd, "the arguments hold")
}

// secretInBody refuses an agent's script, --stdin-file or SQL file that
// holds a vault value.
func secretInBody(what string, b []byte) error {
	if !isAgent() || len(b) > hiddenScanMax || out.P.Secrets == nil || !out.P.HoldsVaultValue(string(b)) {
		return nil
	}
	return secretInputErr(nil, what+" holds")
}
