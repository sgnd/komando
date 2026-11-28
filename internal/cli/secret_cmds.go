package cli

import (
	"errors"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// The secret subcommands that read or store one value: set, get, check,
// list and rm (secret.go has the group, mv and cp).

// secretSetCmd is `credential password add`.
const secretAddLong = `Saves or replaces a password or a token. Replacing one that a production server or
database uses asks first: it changes how komando logs in there. With --new
it only saves a new one: when NAME is in the vault already it stops with
SECRET_EXISTS and leaves the stored value alone.

A value from a pipe loses the line breaks at its end (echo and pbpaste add
one). Spaces are kept, since a password can hold them; komando warns when the
value starts or ends with one, so a stray space copied with a password is
noticed. At the terminal, paste or type the value after the prompt appears.`

func secretSetCmd() *cobra.Command {
	set := &cobra.Command{
		Use:     "set NAME",
		Short:   "Store a secret, typed hidden or from a variable or a pipe",
		Long:    secretAddLong,
		Example: "  komando credential password add web1-pass          # type or paste it after the prompt, nothing is shown\n  komando credential password add db-pass --from-env DB_PASS\n  pbpaste | komando credential password add vpn-pass\n  komando credential token add api-token --new --from-env TOKEN   # never replaces one",
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if err := inventory.ValidName("secret", args[0]); err != nil {
				return err
			}
			if err := reservedSecret(args[0]); err != nil {
				return err
			}
			isNew, _ := cmd.Flags().GetBool("new")
			// a name that is taken fails before anyone types the value; the
			// write below checks again, in the same step, for a komando
			// that stores it meanwhile
			if _, gerr := vault.Get(args[0]); gerr == nil && isNew {
				return secretSetExists(args[0])
			}
			v, err := secretInput(cmd, args[0], "Paste or type the value for "+args[0]+", then press Enter (it stays hidden): ")
			var oe *out.Error
			if err != nil && cl.dryRun() && errors.As(err, &oe) && oe.Code == "NEEDS_PERSON" {
				// a dry run is never blocked: it says whether NAME would be
				// replaced, and that the real run needs the user
				err = cl.policyStop(oe)
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
			if err := loginPlaceStop(cl, secretPlaceChanges(st, args[0])); err != nil {
				return err
			}
			was, gerr := vault.Get(args[0])
			replaced := gerr == nil
			if replaced {
				if prot := inventory.ProtectedUsers(st, inventory.SecretUsers(st, args[0])); len(prot) > 0 && !cl.yesOK() && !confirmProtected(cl, prot) {
					if err := cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
						"secret "+args[0]+" is used by protected "+strings.Join(prot, ", ")+"; replacing it changes how komando logs in there")); err != nil {
						return err
					}
				}
			}
			if err := guardTrustSecret(cl, st, args[0], was, replaced, v, ""); err != nil {
				return err
			}
			res := map[string]any{"name": args[0], "ref": "credential:" + args[0], "replaced": replaced, "action": secretSetAction(cl, replaced)}
			if w := valueWarning(args[0], v); w != "" {
				res["warning"] = w
			}
			if cl.dryRun() {
				res["would_set"] = true
				cl.out.Print("secret.set", textAs{res, textFn(func() string { return changeText(cl.out, res) })}, nil)
				return nil
			}
			put := vault.Set
			if isNew {
				put = vault.Create
			}
			if err := put(cl.storeWrite(), args[0], v); errors.Is(err, vault.ErrExists) {
				return secretSetExists(args[0]) // stored by another komando meanwhile
			} else if err != nil {
				return err
			}
			audit(cl, nil, "secret.set", nil, "", true, map[string]any{"secret": args[0], "replaced": replaced})
			warnCommonWord(cl, args[0], v)
			cl.out.Print("secret.set", textAs{res, textFn(func() string { return changeText(cl.out, res) })}, nil)
			return nil
		}),
	}
	set.Flags().String("from-env", "", "read the value from this environment variable")
	set.Flags().Bool("new", false, "only store a secret that is not in the vault yet; a taken NAME stops with SECRET_EXISTS")
	return set
}

// secretSetExists is `credential password add NAME --new` when NAME is stored already.
func secretSetExists(name string) error {
	return out.Errf(out.ExitConflict, "SECRET_EXISTS",
		"to replace it, run `komando credential password add "+name+"` without --new; or pick another name",
		"secret %q already exists", name)
}

// secretGetCmd is `credential password show` (`credential password show` is a plain synonym); the
// agent mask line keys on its ID, secret.show.
const secretShowLong = `Says whether the secret exists and what uses it, without its value. A person
at a terminal can add --reveal to print it; from a program without a terminal
(the Komando Mac app), komando first asks the person in its own window. AI
agents never get the value (they reference it as credential:NAME instead). A warning says when the value
starts or ends with a space, tab or line break, a common cause of a failing
login; set it again with ` + "`komando credential password add NAME`" + ` if that is not part of it.`

func secretGetCmd() *cobra.Command {
	get := &cobra.Command{
		Use:     "show NAME",
		Aliases: []string{"get"},
		Short:   "Show that a secret exists, its value hidden",
		Long:    secretShowLong,
		Example: `  komando credential password show db-pass
  komando credential password show db-pass --reveal | pbcopy   # a person, at a terminal`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			v, err := vault.Get(args[0])
			if err == vault.ErrNotFound {
				return notFoundSuggest(cl, "secret", args[0], secretNames())
			}
			if err != nil {
				return err
			}
			via := ""
			if cl.reveal() {
				// agents never see passwords (secret_reveal.go); a person at a terminal can
				// still pipe the value, e.g. into pbcopy, and the Mac app asks in
				// komando's window
				if via, err = revealGate(cl, "secret.show", "secret", args[0], "credential:"+args[0]); err != nil {
					return err
				}
			}
			res := map[string]any{"name": args[0], "exists": true, "ref": "credential:" + args[0]}
			if st, err := loadState(); err == nil {
				res["used_by"] = orEmpty(inventory.SecretUsers(st, args[0]))
			}
			if w := valueWarning(args[0], v); w != "" {
				res["warning"] = w
			}
			if via != "" {
				cl.out.NoRedact = true // the person asked for this value
				res["value"] = v
				revealAudit(cl, "secret.reveal", "secret", args[0], via)
			}
			cl.out.Print("secret.show", res, nil)
			return nil
		}),
	}
	return get
}

// secretListCmd is `credential list`.
func secretListCmd() *cobra.Command {
	var limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List secret names, when they changed and what uses them",
		Args:  cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			l, err := vault.List()
			if err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			l = cutRows(cl, l, limit)
			res := secretList{Count: len(l), Secrets: []secretRow{}}
			for _, i := range l {
				res.Secrets = append(res.Secrets, secretRow{Name: i.Name, UpdatedAt: i.UpdatedAt, UsedBy: orEmpty(inventory.SecretUsers(st, i.Name))})
			}
			cl.out.Print("secret.list", res, nil)
			return nil
		}),
	}
	limitFlag(list, &limit, 0, "secrets")
	return list
}

// secretRmCmd is `credential password remove`.
func secretRmCmd() *cobra.Command {
	rm := &cobra.Command{
		Use:   "rm NAME...",
		Short: "Delete secrets for good",
		Example: `  komando credential password remove old-pass
  komando credential password remove a-pass b-pass --dry-run`,
		Args: cobra.MinimumNArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
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
					return notFoundSuggest(cl, "secret", n, have)
				}
				if users := inventory.SecretUsers(st, n); len(users) > 0 {
					return secretInUse(n, users)
				}
			}
			// a deleted secret has no copy: T3 (OD-7)
			if err := guardLocalDelete(cl, dedupe(args), "secrets", "deletes the saved "+nouns(len(dedupe(args)), "secret")+" "+term.JoinAnd(dedupe(args))+" for good"); err != nil {
				return err
			}
			if cl.dryRun() {
				cl.out.Print("secret.rm", textAs{map[string]any{"would_remove": args}, textFn(func() string {
					return "would remove " + nouns(len(args), "secret") + " " + term.JoinAnd(args) + " for good\n"
				})}, nil)
				return nil
			}
			// all or none, and under the state lock (then the vault lock, as
			// moveSecret takes them), so a reference another komando adds
			// meanwhile is seen before its secret is gone
			args = dedupe(args)
			err = storeUpdate(cl, func(s *store.State) error {
				for _, n := range args {
					if users := inventory.SecretUsers(s, n); len(users) > 0 {
						return secretInUse(n, users)
					}
				}
				return vault.DeleteMany(cl.storeWrite(), args)
			})
			audit(cl, nil, "secret.rm", nil, "", err == nil, map[string]any{"secrets": args})
			if errors.Is(err, vault.ErrNotFound) { // removed by another komando meanwhile
				return notFoundSuggest(cl, "secret", strings.TrimPrefix(err.Error(), vault.ErrNotFound.Error()+": "), secretNames())
			}
			if err != nil {
				return err
			}
			removed := any(args)
			if len(args) == 1 {
				removed = args[0] // one name prints as a string, several as a list
			}
			cl.out.Print("secret.rm", textAs{map[string]any{"removed": removed}, textFn(func() string {
				return "removed " + nouns(len(args), "secret") + " " + term.JoinAnd(args) + "\n"
			})}, nil)
			return nil
		}),
	}
	return rm
}
