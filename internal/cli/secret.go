package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/cli/kit/term"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

type secretRow struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
	UsedBy    []string  `json:"used_by"`
}

type secretList struct {
	Count   int         `json:"count"`
	Secrets []secretRow `json:"secrets"`
}

func (l secretList) Text() string {
	if len(l.Secrets) == 0 {
		return term.NoneYet("credentials", "credential password add NAME", "or `komando credential token add NAME`")
	}
	var rows [][]string
	for _, s := range l.Secrets {
		rows = append(rows, []string{s.Name, humanAge(time.Since(s.UpdatedAt)) + " ago", strings.Join(s.UsedBy, ", ")})
	}
	return textTable([]string{"NAME", "UPDATED", "USED BY"}, rows)
}

func secretNames() []string {
	var n []string
	if l, err := vault.List(); err == nil {
		for _, i := range l {
			n = append(n, i.Name)
		}
	}
	return n
}

// reservedSecret refuses the secrets komando keeps for itself: the approval
// code's key is set up by a person (`config approval-code`), never through
// `credential password add`, `mv`, `cp` or `rm`.
func reservedSecret(name string) error {
	if name == approvalSecret {
		return out.Errf(out.ExitUsage, "RESERVED_SECRET", "a person manages it with `komando config approval-code`",
			"secret %s belongs to komando's approval code", name)
	}
	return nil
}

// secretInput reads a value the way `credential password add` and `secret check` take it:
// from --from-env VAR, from a pipe, or typed hidden at the terminal. name is
// the secret's name, for the hint when there is no value.
func secretInput(cmd *cobra.Command, name, label string) (string, error) {
	cl := callOf(cmd)
	if fromEnv, _ := cmd.Flags().GetString("from-env"); fromEnv != "" {
		v, ok := cl.lookupEnv(fromEnv)
		if !ok {
			return "", out.Errf(out.ExitUsage, "USAGE", "export "+fromEnv+" first, or pipe the value in (stdin)", "env %s not set", fromEnv)
		}
		// the same rule as a pipe and the prompt: an empty value is a
		// mistake (a variable exported in another shell), never a password
		if strings.TrimSpace(v) == "" {
			return "", out.Errf(out.ExitUsage, "USAGE", "export "+fromEnv+" with the value first, or pipe the value in (stdin)", "env %s is empty", fromEnv)
		}
		return v, nil
	}
	b, err := readStdinIfPiped(cl, maxStdinValue, "the value")
	if err != nil {
		return "", err
	}
	if b != nil {
		// The line endings at the end of a pipe are not part of the value:
		// echo, pbpaste and files add them. The same rule as file: references.
		v := strings.TrimRight(string(b), "\r\n")
		if strings.TrimSpace(v) == "" {
			return "", out.Usage("the value piped in (stdin) is empty")
		}
		return v, nil
	}
	// a person at a terminal: ask with hidden input. An AI agent is never
	// asked, also when it runs komando under a terminal: it would wait for
	// an answer nobody gives.
	if !cl.interactive() {
		if cl.isAgent() {
			// A password only the user knows is typed by the user. Sending
			// the agent back to --from-env or stdin would make it ask for
			// the password in the chat, where it stays in the transcript.
			path := cmd.CommandPath()
			if cl.out.As != "" { // a leaf runs this body: name the leaf's path
				path = "komando " + strings.ReplaceAll(cl.out.As, ".", " ")
			}
			return "", out.Errf(out.ExitPolicy, "NEEDS_PERSON",
				fmt.Sprintf("ask the user to run `%s %s` in their own terminal: it asks for the value, hidden. Never ask for a password in the chat. A value a program makes (a new token) can be piped in (stdin) or given with --from-env VAR", path, name),
				"no value for %s: a password is typed by the user, so it never passes through an AI agent", name)
		}
		return "", out.Usage("no value: use --from-env VAR or pipe the value in (stdin)")
	}
	v, err := readHidden(cl, label)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", out.Usage("empty value")
	}
	return v, nil
}

// valueWarning describes, without the value, what often means a value was
// stored wrong: a space or tab at either end (copied with the text around
// it), a line break at the end of a one-line value, control characters.
// Empty when nothing looks wrong. It tells one or two bits about the value,
// never its length or content.
func valueWarning(name, v string) string {
	var what []string
	if v != "" && (strings.ContainsAny(v[:1], " \t") || strings.ContainsAny(v[len(v)-1:], " \t")) {
		what = append(what, "starts or ends with a space or tab")
	}
	trimmed := strings.TrimRight(v, "\r\n")
	if trimmed != v && !strings.ContainsAny(trimmed, "\r\n") {
		what = append(what, "ends with a line break")
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f }) {
		what = append(what, "holds control characters")
	}
	if len(what) == 0 {
		return ""
	}
	return "the value of " + name + " " + strings.Join(what, " and ") +
		"; if that is not part of it, set it again (a person can compare it with `komando secret check " + name + "`)"
}

// secretDiff says how a value a person entered differs from the stored
// one, without either value. Only `secret check` uses it, for a person.
func secretDiff(stored, given string) string {
	ends := func(s string) string {
		var e []string
		if strings.TrimLeft(s, " \t\r\n") != s {
			e = append(e, "starts")
		}
		if strings.TrimRight(s, " \t\r\n") != s {
			e = append(e, "ends")
		}
		if len(e) == 0 {
			return ""
		}
		return strings.Join(e, " and ") + " with a space, tab or line break"
	}
	switch {
	case strings.TrimSpace(stored) == strings.TrimSpace(given):
		d := "they differ only in spaces, tabs or line breaks at the start or end"
		if e := ends(stored); e != "" {
			d += "; the stored value " + e
		}
		if e := ends(given); e != "" {
			d += "; the value you entered " + e
		}
		return d
	case strings.EqualFold(stored, given):
		return "they differ only in upper and lower case"
	}
	ns, ng := utf8.RuneCountInString(stored), utf8.RuneCountInString(given)
	if ns == ng {
		return fmt.Sprintf("both have %d characters, but they are different", ns)
	}
	return fmt.Sprintf("the stored value has %d characters, the one you entered %d", ns, ng)
}

const secretLong = `Save a password once, then point to it as secret:NAME instead of typing it:
  komando credential password add web1-pass
  komando host edit web1 --password-ref secret:web1-pass

komando shows a saved value only to a person: at a terminal with
` + "`credential password show --reveal`" + `, or after "Allow once" in komando's window; never
to an AI agent. ` + "`secret check`" + ` compares a value with the saved one
without showing either. ` + "`credential password rename`" + ` and ` + "`secret cp`" + ` rename and copy.

How it is stored: each secret sealed with AES-256-GCM in ~/.komando/store.db.
The random key is in the OS keychain (or in store.key where there is none,
or with KOMANDO_KEYCHAIN=off), or comes from $KOMANDO_VAULT_PASS when that is
set at first use (` + "`config vault passphrase`" + ` changes it).

A --password-ref (and the other -ref flags) can also read a password your
team keeps elsewhere; komando reads it when needed and never stores it:
  env:VAR  file:PATH  vault:PATH#FIELD  aws-sm:NAME[#KEY]  gcp-sm:NAME[@PROJECT]
  azure-kv:VAULT/NAME[#KEY]  op://VAULT/ITEM/FIELD  bw://ITEM/FIELD  kdbx:FILE#GROUP/ENTRY`

func secretCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets", "vault"},
		Short:   "Check or copy a saved password or token",
		Long:    secretLong,
	}
	// the other commands run as the credential and config vault leaves;
	// check and cp go in cut step D
	c.AddCommand(secretCheckCmd(), addAliases(secretCopyCmd(false), "copy"))
	return c
}

// The credential leaves run today's secret, key and host ca bodies. Until
// cut step E keeps a kind with each saved value, the password and the token
// leaves run the same body.
func init() {
	for verb, body := range map[string]func() *cobra.Command{"add": secretSetCmd, "show": secretGetCmd,
		"remove": secretRmCmd, "rename": func() *cobra.Command { return secretCopyCmd(true) }} {
		for _, kind := range []string{"password", "token"} {
			handlers[capability.Key{Type: "credential", Area: kind, Verb: verb}] = bodyHandler(body)
		}
	}
	handlers[capability.Key{Type: "credential", Verb: "list"}] = bodyHandler(secretListCmd)
	handlers[capability.Key{Type: "credential", Verb: "run"}] = bodyHandler(runCmd)
	for verb, body := range map[string]func() *cobra.Command{"add": keyAddCmd, "create": keyGenCmd, "edit": keyEditCmd,
		"install": keyDeployCmd, "uninstall": keyRevokeCmd, "list": keyListCmd, "remove": keyRmCmd, "rename": keyMvCmd, "show": keyShowCmd} {
		handlers[capability.Key{Type: "credential", Area: "key", Verb: verb}] = bodyHandler(body)
	}
	for verb, body := range map[string]func() *cobra.Command{"add": hostCAAddCmd, "list": hostCAListCmd, "remove": hostCARmCmd} {
		handlers[capability.Key{Type: "credential", Area: "certificate", Verb: verb}] = bodyHandler(body)
	}
	moveType("credential")
	helpGroups["credential"] = "access"
	groupShorts["credential"] = "Saved passwords, tokens, SSH keys and server CAs"
	groupShorts["credential password"] = "Saved passwords: add, show, rename, remove"
	groupShorts["credential token"] = "Saved tokens: add, show, rename, remove"
	groupShorts["credential key"] = "SSH keys: make, add, install on servers, uninstall"
	groupShorts["credential certificate"] = "Server CAs: trust the CA that signs servers' host keys"
	// the leaves keep the longer help of today's bodies
	details["komando credential key create"] = keyCreateLong
	details["komando credential key add"] = keyAddLong
	details["komando credential key edit"] = keyEditLong
	details["komando credential key show"] = keyShowLong
	details["komando credential key remove"] = keyRemoveLong
	details["komando credential key install"] = keyInstallLong
	details["komando credential key rename"] = keyRenameLong
	details["komando credential key uninstall"] = keyUninstallLong
	details["komando credential certificate add"] = certificateAddLong
	details["komando credential certificate remove"] = certificateRemoveLong
	details["komando credential password add"] = secretAddLong
	details["komando credential token add"] = secretAddLong
	details["komando credential password show"] = secretShowLong
	details["komando credential token show"] = secretShowLong
	details["komando credential run"] = credentialRunLong
}

// bodyHandler runs body, today's command, with what the leaf was given.
func bodyHandler(body func() *cobra.Command) handler {
	return func(cl *call, ctx context.Context, in leafInput) error {
		return runBody(cl, ctx, body(), in, nil)
	}
}

// secretCopyCmd is `credential password rename` (move) or `secret cp`. The value is copied
// inside the vault and never printed, so an AI agent can rename a secret it
// cannot read. mv also points every server, conn, key and VPN that used the
// old name at the new one, in the same step.
func secretCopyCmd(move bool) *cobra.Command {
	var overwrite bool
	verb, command := "cp", "secret.cp"
	short := "Copy a secret to a new name in the vault (value never shown)"
	long := `Stores the value of OLD under NEW as well. The value stays inside the vault:
it is never printed, so an AI agent can do this too. Nothing that uses OLD
changes.`
	example := "  komando secret cp db-pass db-pass-old\n  komando secret cp web-pass shared-pass --overwrite"
	if move {
		verb, command = "rename", "secret.rename"
		short = "Rename a secret and every reference to it (value never shown)"
		long = `Renames OLD to NEW inside the vault, and points every server, conn, key and
VPN that used secret:OLD at secret:NEW in the same step, so nothing stops
working and nobody types the value again. The value is never printed, so an
AI agent can do this too. Scripts or notes of your own that name secret:OLD
are not changed.`
		example = "  komando credential password rename vpn-password office-vpn-pass --dry-run\n  komando credential password rename vpn-password office-vpn-pass"
	}
	c := &cobra.Command{
		Use:     verb + " OLD NEW",
		Short:   short,
		Long:    long + "\n\nWhen NEW exists already, --overwrite replaces its value; when a protected\nserver or conn uses NEW, that also needs --yes.",
		Example: example,
		Args:    cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			from, to := args[0], args[1]
			if err := inventory.ValidName("secret", to); err != nil {
				return err
			}
			for _, n := range args {
				if err := reservedSecret(n); err != nil {
					return err
				}
			}
			if from == to {
				return out.Usage("the old and the new name are the same")
			}
			have := secretNames()
			if !slices.Contains(have, from) {
				return notFoundSuggest(cl, "secret", from, have)
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			replaced := slices.Contains(have, to)
			if err := secretCopyStops(cl, st, from, to, replaced, overwrite); err != nil {
				return err
			}
			// what uses NEW gets the value of OLD: for a profile or a CA
			// certificate that is a new place or a new trust
			if err := guardCopyTrust(cl, st, from, to, replaced); err != nil {
				return err
			}
			res := map[string]any{"from": from, "to": to, "ref": "secret:" + to, "replaced": replaced}
			if cl.dryRun() {
				res[map[bool]string{true: "would_move", false: "would_copy"}[move]] = true
				if move {
					res["would_update"] = orEmpty(inventory.SecretUsers(st, from))
				}
				cl.out.Print(command, textAs{res, secretCopyText(cl, move, res)}, nil)
				return nil
			}
			var updated []string
			if move {
				updated, err = moveSecret(cl, from, to, overwrite)
			} else {
				err = vault.Copy(cl.storeWrite(), from, to, overwrite)
			}
			rec := map[string]any{"from": from, "to": to, "replaced": replaced}
			if move {
				rec["updated"] = orEmpty(updated)
			}
			audit(cl, nil, command, nil, "", err == nil, rec)
			switch {
			case errors.Is(err, vault.ErrExists): // made by another komando meanwhile
				return secretExists(from, to)
			case errors.Is(err, vault.ErrNotFound):
				return notFoundSuggest(cl, "secret", from, secretNames())
			case err != nil:
				return err
			}
			if move {
				res["updated"] = orEmpty(updated)
			}
			cl.out.Print(command, textAs{res, secretCopyText(cl, move, res)}, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace NEW when it exists (what uses NEW then gets the value of OLD)")
	if move {
		c.Aliases = []string{"mv"} // a plain synonym
	}
	return c
}

// guardCopyTrust is guardTrustSecret for secret cp and rename: what uses
// TO gets the value of FROM, which the agent may not read, so the window
// names FROM, never what is in it.
func guardCopyTrust(cl *call, st *store.State, from, to string, replaced bool) error {
	if !cl.isAgent() {
		return nil
	}
	now, err := vault.Get(from)
	if err != nil {
		return err
	}
	was, _ := vault.Get(to)
	return guardTrustSecret(cl, st, to, was, replaced, now, "secret "+from)
}

func secretExists(from, to string) error {
	return out.Errf(out.ExitConflict, "SECRET_EXISTS",
		"pick another name, or add --overwrite to replace it (what uses "+to+" then gets the value of "+from+")",
		"secret %q already exists", to)
}

// moveSecret renames the secret in the vault and its references in the
// state in one step: under the state lock (then the vault lock, the order
// every komando command takes them in), the references change only when
// the vault rename worked, and OLD is put back in the vault when the state
// cannot be saved. It returns what now uses the new name.
func moveSecret(cl *call, from, to string, overwrite bool) ([]string, error) {
	var updated []string
	renamed := false
	err := storeUpdate(cl, func(s *store.State) error {
		updated = inventory.RenameSecretRefs(s, from, to)
		if err := vault.Rename(cl.storeWrite(), from, to, overwrite); err != nil {
			return err
		}
		renamed = true
		return nil
	})
	switch {
	case err == nil || !renamed:
	case overwrite: // the value NEW had is gone; OLD comes back, NEW keeps its new value
		_ = vault.Copy(cl.storeWrite(), to, from, false)
	default:
		_ = vault.Rename(cl.storeWrite(), to, from, false)
	}
	return updated, err
}

const vaultKeychainLong = `Moves the vault's key out of the store.key file into the operating system's
keychain, so a copy of ` + "~/.komando" + ` (a backup, a synced folder) no longer opens
the vault or its secrets. The vault gets a new key as it moves, so a copy of store.key
made before opens nothing either, and the vault keeps every secret.
--off moves the key back into store.key, which needs --yes.

Only a person at a terminal moves the key in: the keychain may ask them to
unlock it, and an AI agent or a script cannot answer that.`

func secretKeychainCmd() *cobra.Command {
	var off bool
	c := &cobra.Command{
		Use:     "keychain",
		Short:   "Keep the vault key in the OS keychain instead of store.key",
		Long:    vaultKeychainLong,
		Example: "  komando config vault keychain\n  komando config vault keychain --off --yes",
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			if !off && (cl.isAgent() || !cl.interactive()) {
				// an unlock prompt nobody answers would keep komando waiting
				err := cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON", "ask the user to run `komando config vault keychain` in their own terminal",
					"only a person at a terminal can move the vault key into the keychain: it may ask them to unlock it"))
				if err != nil {
					return err
				}
			}
			if cl.dryRun() {
				tool, err := vault.KeychainTool()
				res := map[string]any{"dry_run": true, "would": map[bool]string{false: "move the vault key into the keychain", true: "move the vault key back into store.key"}[off]}
				if err != nil {
					res["problem"] = err.Error()
				} else {
					res["keychain"] = tool
				}
				cl.out.Print("secret.keychain", res, nil)
				return nil
			}
			if off {
				if err := guardSafety(cl, "moving the vault key out of the keychain into a file"); err != nil {
					return err
				}
				err := vault.KeyToFile()
				audit(cl, nil, "secret.keychain", nil, "", err == nil, map[string]any{"key": "file"})
				if err != nil {
					return out.Errf(out.ExitRemote, "KEYCHAIN_FAILED", "a person unlocks the keychain on this computer (an AI agent asks the user), then run it again; on Linux it needs secret-tool and a keyring", "%v", err)
				}
				cl.out.Print("secret.keychain", map[string]any{"key": "store.key"}, nil)
				return nil
			}
			tool, err := vault.KeyToKeychain()
			audit(cl, nil, "secret.keychain", nil, "", err == nil, map[string]any{"key": "keychain"})
			if errors.Is(err, vault.ErrKeychainTaken) {
				return out.Errf(out.ExitConflict, "KEYCHAIN_TAKEN", "put back the vault you moved aside, or once no vault needs that key, a person deletes the keychain item (an AI agent asks the user), then run it again", "%v; the vault still uses store.key, nothing was lost", err)
			}
			if err != nil {
				return out.Errf(out.ExitRemote, "KEYCHAIN_FAILED", "a person unlocks the keychain (an AI agent asks the user), then run it again; on Linux it needs secret-tool and a keyring", "%v; the vault still uses store.key, nothing was lost", err)
			}
			cl.out.Print("secret.keychain", map[string]any{"key": "keychain", "keychain": tool, "vault_key_file": "removed"}, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&off, "off", false, "move the key back into store.key (needs --yes)")
	return c
}

// secretInUse names the command that points the first user elsewhere.
func secretInUse(name string, users []string) error {
	kind, who, _ := strings.Cut(users[0], " ")
	hint := map[string]string{
		"host": "komando host edit " + who + " --password-ref ... (or --sudo-ref ..., --env ...)",
		"conn": "komando conn edit " + who + " --password-ref ...",
		"key":  "komando credential key edit " + who + " --passphrase-credential ...",
		"vpn":  "komando vpn KIND edit " + who + " ...",
	}[kind]
	return out.Errf(out.ExitConflict, "SECRET_IN_USE", "point them at another secret first, for example `"+hint+"`, or rename it with `komando credential password rename`",
		"secret %s is used by %s", name, strings.Join(users, ", "))
}

// secretSetAction says what secret set did, or would do under --dry-run,
// for the text headline ("stored db-pass", "would replace db-pass").
func secretSetAction(cl *call, replaced bool) string {
	if cl.dryRun() {
		return map[bool]string{false: "would_store", true: "would_replace"}[replaced]
	}
	return map[bool]string{false: "stored", true: "replaced"}[replaced]
}

// secretCopyText is secret rename's and secret cp's text: what moved
// where, and what follows the new name.
func secretCopyText(cl *call, move bool, res map[string]any) out.Texter {
	return textFn(func() string {
		verb := map[bool]string{true: "renamed", false: "copied"}[move]
		if cl.dryRun() {
			verb = map[bool]string{true: "would rename", false: "would copy"}[move]
		}
		s := fmt.Sprintf("%s secret %v to %v", verb, res["from"], res["to"])
		if res["replaced"] == true {
			s += " (its old value replaced)"
		}
		users, _ := res["updated"].([]string)
		if cl.dryRun() {
			users, _ = res["would_update"].([]string)
		}
		if len(users) > 0 {
			s += "\n  " + map[bool]string{true: "would point at ", false: "now points at "}[cl.dryRun()] + res["ref"].(string) + ": " + strings.Join(users, ", ")
		}
		return s + "\n"
	})
}

// secretCopyStops are the stops before secret cp/mv writes to: a name
// taken without --overwrite, a secret on the way to a login-ask server or
// conn (loginPlaceStop), and one a protected entry uses.
func secretCopyStops(cl *call, st *store.State, from, to string, replaced, overwrite bool) error {
	if replaced && !overwrite {
		return secretExists(from, to)
	}
	if err := loginPlaceStop(cl, secretPlaceChanges(st, to)); err != nil {
		return err
	}
	if !replaced {
		return nil
	}
	if prot := inventory.ProtectedUsers(st, inventory.SecretUsers(st, to)); len(prot) > 0 && !cl.yesOK() && !confirmProtected(cl, prot) {
		return cl.policyStop(approvalErr(cl, "PROTECTED_TARGET",
			"secret "+to+" is used by protected "+strings.Join(prot, ", ")+"; replacing it changes how komando logs in there"))
	}
	return nil
}

// commonPasswords are values people often pick that the letters-only rule
// of commonWord does not catch; compared without case.
var commonPasswords = map[string]bool{
	"123456": true, "1234567": true, "12345678": true, "123456789": true, "1234567890": true,
	"password": true, "password1": true, "password123": true, "passw0rd": true, "p@ssw0rd": true,
	"qwerty": true, "qwerty123": true, "abc123": true, "letmein": true, "welcome": true, "welcome1": true,
	"admin": true, "admin123": true, "root": true, "toor": true, "changeme": true, "secret": true,
	"iloveyou": true, "monkey": true, "dragon": true, "111111": true, "000000": true,
}

// commonWord reports whether v is a common word: only letters and shorter
// than 10 characters, or a common password. Such a value is easy to guess,
// and komando hides that word wherever it appears in its output.
func commonWord(v string) bool {
	if commonPasswords[strings.ToLower(v)] {
		return true
	}
	if v == "" || len(v) >= 10 {
		return false
	}
	for _, r := range v {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// commonWordWarning is the warning for a secret whose value is a common
// word; it names the secret, never the value.
func commonWordWarning(name string) string {
	return "secret " + name + ": this value is a common word and easy to guess; use a longer value or add digits or symbols (a value of 6 or more characters is also hidden wherever that word appears in komando's output)"
}

// warnCommonWord warns, on stderr and in meta.warnings, when the value
// stored as name is a common word.
func warnCommonWord(cl *call, name, v string) {
	if commonWord(v) {
		cl.out.Warn(commonWordWarning(name))
	}
}

// storeImportSecrets puts the named values in the vault, warning about
// each that is a common word.
func storeImportSecrets(cl *call, names []string, values map[string]string) error {
	for _, name := range names {
		if err := vault.Set(cl.storeWrite(), name, values[name]); err != nil {
			return err
		}
		warnCommonWord(cl, name, values[name])
	}
	return nil
}
