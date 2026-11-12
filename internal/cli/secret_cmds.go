package cli

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The secret subcommands that read or store one value: set, get, check,
// list and rm (secret.go has the group, mv and cp).

// secretSetCmd is `secret set`.
func secretSetCmd() *cobra.Command {
	set := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret (typed hidden, or from --from-env VAR or stdin)",
		Long: `Saves or replaces a password. Replacing one that a production server or
database uses asks first: it changes how komando logs in there.

A value from a pipe loses the line breaks at its end (echo and pbpaste add
one). Spaces are kept, since a password can hold them; komando warns when the
value starts or ends with one, so a stray space copied with a password is
noticed. At the terminal, paste or type the value after the prompt appears.`,
		Example: "  komando secret set web1-pass          # type or paste it after the prompt, nothing is shown\n  komando secret set db-pass --from-env DB_PASS\n  pbpaste | komando secret set vpn-pass",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validName("secret", args[0]); err != nil {
				return err
			}
			if err := reservedSecret(args[0]); err != nil {
				return err
			}
			if len(args) == 2 {
				// A value on the command line lands in shell history and in
				// `ps` for every user on the machine.
				return out.Errf(out.ExitUsage, "SECRET_IN_ARGS",
					fmt.Sprintf("run `komando secret set %s` and type it (hidden), use --from-env VAR, or pipe it on stdin", args[0]),
					"refusing a secret value on the command line: it would be saved in shell history")
			}
			v, err := secretInput(cmd, args[0], "Paste or type the value for "+args[0]+", then press Enter (it stays hidden): ")
			var oe *out.Error
			if err != nil && g.dryRun && errors.As(err, &oe) && oe.Code == "NEEDS_PERSON" {
				// a dry run is never blocked: it says whether NAME would be
				// replaced, and that the real run needs the user
				err = policyStop(oe)
			}
			if err != nil {
				return err
			}
			if out.HasHidden(v) {
				return hiddenValueErr()
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			_, gerr := vault.Get(args[0])
			replaced := gerr == nil
			if replaced {
				if prot := protectedUsers(st, secretUsers(st, args[0])); len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
					if err := policyStop(out.Errf(out.ExitPolicy, "PROTECTED_TARGET", "re-run with --yes after the user confirms",
						"secret %s is used by protected %s; replacing it changes how komando logs in there", args[0], strings.Join(prot, ", "))); err != nil {
						return err
					}
				}
			}
			res := map[string]any{"name": args[0], "ref": "secret:" + args[0], "replaced": replaced, "action": secretSetAction(replaced)}
			if w := valueWarning(args[0], v); w != "" {
				res["warning"] = w
			}
			if g.dryRun {
				res["would_set"] = true
				out.P.Print("secret.set", res, nil)
				return nil
			}
			if err := vault.Set(args[0], v); err != nil {
				return err
			}
			audit(nil, "secret.set", nil, "", true, map[string]any{"secret": args[0], "replaced": replaced})
			out.P.Print("secret.set", res, nil)
			return nil
		},
	}
	set.Flags().String("from-env", "", "read the value from this environment variable")
	return set
}

// secretGetCmd is `secret show` (`secret get` before, a permanent synonym;
// the ID stays secret.get, so the agent mask line keys it as before).
func secretGetCmd() *cobra.Command {
	get := &cobra.Command{
		Use:     "show NAME",
		Aliases: []string{"get"},
		Short:   "Check a secret exists; --reveal prints its value",
		Long: `Says whether the secret exists and what uses it, without its value. A person
at a terminal can add --reveal to print it; AI agents never get the value
(they reference it as secret:NAME instead). A warning says when the value
starts or ends with a space, tab or line break, a common cause of a failing
login; 'komando secret check NAME' lets a person compare it.`,
		Example: `  komando secret show db-pass
  komando secret show db-pass --reveal | pbcopy   # a person, at a terminal`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := vault.Get(args[0])
			if err == vault.ErrNotFound {
				return notFoundSuggest("secret", args[0], secretNames())
			}
			if err != nil {
				return err
			}
			reveal := g.reveal
			if reveal && !interactive() {
				// agents never see passwords (docs/design/vision.md); a person at
				// a terminal can still pipe the value, e.g. into pbcopy
				return out.Errf(out.ExitPolicy, "REVEAL_NEEDS_HUMAN",
					"ask a person to run `komando secret show "+args[0]+" --reveal` in a terminal; to use the secret in a command, reference it (secret:"+args[0]+") instead",
					"--reveal only works for a person at a terminal")
			}
			res := map[string]any{"name": args[0], "exists": true, "ref": "secret:" + args[0]}
			if st, err := loadState(); err == nil {
				res["used_by"] = orEmpty(secretUsers(st, args[0]))
			}
			if w := valueWarning(args[0], v); w != "" {
				res["warning"] = w
			}
			if reveal {
				out.P.NoRedact = true // the person asked for this value
				res["value"] = v
				audit(nil, "secret.reveal", nil, "", true, map[string]any{"secret": args[0]})
			}
			out.P.Print("secret.get", res, nil)
			return nil
		},
	}
	withID(get, "secret.get")
	return get
}

// secretCheckCmd is `secret check`.
func secretCheckCmd() *cobra.Command {
	check := &cobra.Command{
		Use:   "check NAME",
		Short: "Compare a typed value to a secret; shows neither (a person only)",
		Long: `Asks for a value (hidden, or from --from-env VAR or a pipe) and says whether it
is the stored one. When it is not, it says how they differ (only spaces at
the ends, only upper and lower case, or the number of characters), but never
shows either value.

Only a person can run it: for an AI agent, a yes/no answer about a value it
picks would be a way to guess the secret one try at a time.`,
		Example: "  komando secret check vpn-pass            # type or paste it after the prompt\n  pbpaste | komando secret check vpn-pass",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAgent() {
				return out.Errf(out.ExitPolicy, "NEEDS_PERSON",
					"ask the user to run `komando secret check "+args[0]+"` in their own terminal; `komando secret show "+args[0]+"` says whether the value starts or ends with a space",
					"only a person can check a secret's value: for an AI agent it would be a way to guess it")
			}
			stored, err := vault.Get(args[0])
			if err == vault.ErrNotFound {
				return notFoundSuggest("secret", args[0], secretNames())
			}
			if err != nil {
				return err
			}
			given, err := secretInput(cmd, args[0], "Paste or type the value to compare with "+args[0]+", then press Enter (it stays hidden): ")
			if err != nil {
				return err
			}
			match := subtle.ConstantTimeCompare([]byte(stored), []byte(given)) == 1
			audit(nil, "secret.check", nil, "", true, map[string]any{"secret": args[0], "match": match})
			res := map[string]any{"name": args[0], "match": match}
			if match {
				out.P.Print("secret.check", res, nil)
				return nil
			}
			res["difference"] = secretDiff(stored, given)
			out.P.Print("secret.check", res, &out.Error{Code: "SECRET_MISMATCH", Exit: out.ExitError,
				Message: "the value is not the one stored in " + args[0],
				Hint:    "if the stored one is wrong, store the right one with `komando secret set " + args[0] + "`"})
			return exitCode(out.ExitError)
		},
	}
	check.Flags().String("from-env", "", "read the value to compare from this environment variable")
	return check
}

// secretListCmd is `secret list`.
func secretListCmd() *cobra.Command {
	var limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List secret names, when they changed and what uses them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			l, err := vault.List()
			if err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			l = cutRows(l, limit)
			res := secretList{Count: len(l), Secrets: []secretRow{}}
			for _, i := range l {
				res.Secrets = append(res.Secrets, secretRow{Name: i.Name, UpdatedAt: i.UpdatedAt, UsedBy: orEmpty(secretUsers(st, i.Name))})
			}
			out.P.Print("secret.list", res, nil)
			return nil
		},
	}
	limitFlag(list, &limit, 0, "secrets")
	return list
}

// secretRmCmd is `secret rm`.
func secretRmCmd() *cobra.Command {
	rm := &cobra.Command{
		Use:   "rm NAME...",
		Short: "Delete secrets (refused while anything still uses them)",
		Example: `  komando secret rm old-pass
  komando secret rm a-pass b-pass --dry-run`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			have := secretNames()
			for _, n := range args {
				if err := reservedSecret(n); err != nil {
					return err
				}
				if !slices.Contains(have, n) {
					return notFoundSuggest("secret", n, have)
				}
				if users := secretUsers(st, n); len(users) > 0 {
					return secretInUse(n, users)
				}
			}
			if g.dryRun {
				out.P.Print("secret.rm", map[string]any{"would_remove": args}, nil)
				return nil
			}
			// all or none, and under the state lock (then the vault lock, as
			// moveSecret takes them), so a reference another komando adds
			// meanwhile is seen before its secret is gone
			args = dedupe(args)
			err = store.Update(func(s *store.State) error {
				for _, n := range args {
					if users := secretUsers(s, n); len(users) > 0 {
						return secretInUse(n, users)
					}
				}
				return vault.DeleteMany(args)
			})
			audit(nil, "secret.rm", nil, "", err == nil, map[string]any{"secrets": args})
			if errors.Is(err, vault.ErrNotFound) { // removed by another komando meanwhile
				return notFoundSuggest("secret", strings.TrimPrefix(err.Error(), vault.ErrNotFound.Error()+": "), secretNames())
			}
			if err != nil {
				return err
			}
			removed := any(args)
			if len(args) == 1 {
				removed = args[0] // one name prints as a string, several as a list
			}
			out.P.Print("secret.rm", map[string]any{"removed": removed}, nil)
			return nil
		},
	}
	return rm
}
