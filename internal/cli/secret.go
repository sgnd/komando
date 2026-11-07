package cli

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

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
		return "no secrets yet: komando secret set NAME\n"
	}
	var rows [][]string
	for _, s := range l.Secrets {
		rows = append(rows, []string{s.Name, humanAge(time.Since(s.UpdatedAt)) + " ago", strings.Join(s.UsedBy, ", ")})
	}
	return textTable([]string{"NAME", "UPDATED", "USED_BY"}, rows)
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

// protectedUsers are the protected servers and conns among users.
func protectedUsers(st *store.State, users []string) []string {
	var prot []string
	for _, u := range users {
		kind, name, _ := strings.Cut(u, " ")
		if (kind == "host" && st.Hosts[name] != nil && st.Hosts[name].Protected) || (kind == "conn" && st.Conns[name] != nil && st.Conns[name].Protected) {
			prot = append(prot, u)
		}
	}
	return prot
}

// reservedSecret refuses the secrets komando keeps for itself: the approval
// code's key is set up by a person (`config approval-code`), never through
// `secret set`, `mv`, `cp` or `rm`.
func reservedSecret(name string) error {
	if name == approvalSecret {
		return out.Errf(out.ExitUsage, "RESERVED_SECRET", "a person manages it with `komando config approval-code`",
			"secret %s belongs to komando's approval code", name)
	}
	return nil
}

// secretInput reads a value the way `secret set` and `secret check` take it:
// from --from-env VAR, from a pipe, or typed hidden at the terminal.
func secretInput(cmd *cobra.Command, label string) (string, error) {
	if fromEnv, _ := cmd.Flags().GetString("from-env"); fromEnv != "" {
		v, ok := os.LookupEnv(fromEnv)
		if !ok {
			return "", out.Errf(out.ExitUsage, "USAGE", "export "+fromEnv+" first, or pipe the value on stdin", "env %s not set", fromEnv)
		}
		return v, nil
	}
	b, err := readStdinIfPiped()
	if err != nil {
		return "", err
	}
	if b != nil {
		// The line endings at the end of a pipe are not part of the value:
		// echo, pbpaste and files add them. The same rule as file: references.
		v := strings.TrimRight(string(b), "\r\n")
		if strings.TrimSpace(v) == "" {
			return "", out.Usage("empty value on stdin")
		}
		return v, nil
	}
	// a person at a terminal: ask with hidden input (agents never have a TTY)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", out.Usage("no value: use --from-env VAR or pipe the value on stdin")
	}
	v, err := readHidden(label)
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

func secretCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "secret",
		Aliases: []string{"secrets", "vault"},
		Short:   "Encrypted vault for passwords and tokens (secret:NAME)",
		Long: `Secrets are AES-256-GCM encrypted in ~/.komando/vault.json. The key comes from
$KOMANDO_VAULT_PASS if set at first use, otherwise a random vault.key file.
Values are never printed unless 'secret get --reveal' is used (a person only).
'secret mv' and 'secret cp' rename and copy inside the vault, so nobody has to
type a value again; 'secret check' lets a person compare a value with the
stored one without showing either.`,
	}
	set := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret (asks for it hidden; or from --from-env VAR or stdin)",
		Long: `Stores or replaces a secret. Replacing one that a protected server or conn
uses needs --yes: it changes how komando logs in there.

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
			v, err := secretInput(cmd, "Paste or type the value for "+args[0]+", then press Enter (it stays hidden): ")
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
			res := map[string]any{"name": args[0], "ref": "secret:" + args[0], "replaced": replaced}
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
	get := &cobra.Command{
		Use:   "get NAME",
		Short: "Check a secret exists; --reveal prints its value",
		Long: `Says whether the secret exists and what uses it, without its value. A person
at a terminal can add --reveal to print it; AI agents never get the value
(they reference it as secret:NAME instead). A warning says when the value
starts or ends with a space, tab or line break, a common cause of a failing
login; 'komando secret check NAME' lets a person compare it.`,
		Example: `  komando secret get db-pass
  komando secret get db-pass --reveal | pbcopy   # a person, at a terminal`,
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
					"ask a person to run `komando secret get "+args[0]+" --reveal` in a terminal; to use the secret in a command, reference it (secret:"+args[0]+") instead",
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
	check := &cobra.Command{
		Use:   "check NAME",
		Short: "Compare a secret with a value you enter, without showing either (a person only)",
		Long: `Asks for a value (hidden, or from --from-env VAR or a pipe) and says whether it
is the stored one. When it is not, it says how they differ - only spaces at
the ends, only upper and lower case, or the number of characters - but never
shows either value.

Only a person can run it: for an AI agent, a yes/no answer about a value it
picks would be a way to guess the secret one try at a time.`,
		Example: "  komando secret check vpn-pass            # type or paste it after the prompt\n  pbpaste | komando secret check vpn-pass",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if isAgent() {
				return out.Errf(out.ExitPolicy, "NEEDS_PERSON",
					"ask the user to run `komando secret check "+args[0]+"` in their own terminal; `komando secret get "+args[0]+"` says whether the value starts or ends with a space",
					"only a person can check a secret's value: for an AI agent it would be a way to guess it")
			}
			stored, err := vault.Get(args[0])
			if err == vault.ErrNotFound {
				return notFoundSuggest("secret", args[0], secretNames())
			}
			if err != nil {
				return err
			}
			given, err := secretInput(cmd, "Paste or type the value to compare with "+args[0]+", then press Enter (it stays hidden): ")
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
			res := secretList{Count: len(l), Secrets: []secretRow{}}
			for _, i := range l {
				res.Secrets = append(res.Secrets, secretRow{Name: i.Name, UpdatedAt: i.UpdatedAt, UsedBy: orEmpty(secretUsers(st, i.Name))})
			}
			out.P.Print("secret.list", res, nil)
			return nil
		},
	}
	rm := &cobra.Command{
		Use:   "rm NAME...",
		Short: "Delete secrets (refused while a server, conn, key or VPN uses them)",
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
				if !contains(have, n) {
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
			for _, n := range args {
				if err := vault.Delete(n); err != nil && err != vault.ErrNotFound {
					return err
				}
			}
			audit(nil, "secret.rm", nil, "", true, map[string]any{"secrets": args})
			removed := any(args)
			if len(args) == 1 {
				removed = args[0] // one name stays a string, as before
			}
			out.P.Print("secret.rm", map[string]any{"removed": removed}, nil)
			return nil
		},
	}
	c.AddCommand(set, get, check, list, secretCopyCmd(true), secretCopyCmd(false), rm, secretKeychainCmd())
	return c
}

// secretCopyCmd is `secret mv` (move) or `secret cp`. The value is copied
// inside the vault and never printed, so an AI agent can rename a secret it
// cannot read. mv also points every server, conn, key and VPN that used the
// old name at the new one, in the same step.
func secretCopyCmd(move bool) *cobra.Command {
	var overwrite bool
	verb, command := "cp", "secret.cp"
	short := "Copy a secret to a new name inside the vault (the value is never shown)"
	long := `Stores the value of OLD under NEW as well. The value stays inside the vault:
it is never printed, so an AI agent can do this too. Nothing that uses OLD
changes.`
	example := "  komando secret cp db-pass db-pass-old\n  komando secret cp web-pass shared-pass --overwrite"
	if move {
		verb, command = "mv", "secret.mv"
		short = "Rename a secret, and every reference to it (the value is never shown)"
		long = `Renames OLD to NEW inside the vault, and points every server, conn, key and
VPN that used secret:OLD at secret:NEW in the same step, so nothing stops
working and nobody types the value again. The value is never printed, so an
AI agent can do this too. Scripts or notes of your own that name secret:OLD
are not changed.`
		example = "  komando secret mv vpn-password office-vpn-pass --dry-run\n  komando secret mv vpn-password office-vpn-pass"
	}
	c := &cobra.Command{
		Use:     verb + " OLD NEW",
		Short:   short,
		Long:    long + "\n\nWhen NEW exists already, --overwrite replaces its value; when a protected\nserver or conn uses NEW, that also needs --yes.",
		Example: example,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, to := args[0], args[1]
			if err := validName("secret", to); err != nil {
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
			if !contains(have, from) {
				return notFoundSuggest("secret", from, have)
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			replaced := contains(have, to)
			if replaced && !overwrite {
				return secretExists(from, to)
			}
			if replaced {
				if prot := protectedUsers(st, secretUsers(st, to)); len(prot) > 0 && !yesOK() && !confirmProtected(prot) {
					if err := policyStop(out.Errf(out.ExitPolicy, "PROTECTED_TARGET", "re-run with --yes after the user confirms",
						"secret %s is used by protected %s; replacing it changes how komando logs in there", to, strings.Join(prot, ", "))); err != nil {
						return err
					}
				}
			}
			res := map[string]any{"from": from, "to": to, "ref": "secret:" + to, "replaced": replaced}
			if g.dryRun {
				res[map[bool]string{true: "would_move", false: "would_copy"}[move]] = true
				if move {
					res["would_update"] = orEmpty(secretUsers(st, from))
				}
				out.P.Print(command, res, nil)
				return nil
			}
			var updated []string
			if move {
				updated, err = moveSecret(from, to, overwrite)
			} else {
				err = vault.Copy(from, to, overwrite)
			}
			rec := map[string]any{"from": from, "to": to, "replaced": replaced}
			if move {
				rec["updated"] = orEmpty(updated)
			}
			audit(nil, command, nil, "", err == nil, rec)
			switch {
			case errors.Is(err, vault.ErrExists): // made by another komando meanwhile
				return secretExists(from, to)
			case errors.Is(err, vault.ErrNotFound):
				return notFoundSuggest("secret", from, secretNames())
			case err != nil:
				return err
			}
			if move {
				res["updated"] = orEmpty(updated)
			}
			out.P.Print(command, res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace NEW when it exists (what uses NEW then gets the value of OLD)")
	return c
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
func moveSecret(from, to string, overwrite bool) ([]string, error) {
	var updated []string
	renamed := false
	err := store.Update(func(s *store.State) error {
		updated = renameSecretRefs(s, from, to)
		if err := vault.Rename(from, to, overwrite); err != nil {
			return err
		}
		renamed = true
		return nil
	})
	switch {
	case err == nil || !renamed:
	case overwrite: // the value NEW had is gone; OLD comes back, NEW keeps its new value
		_ = vault.Copy(to, from, false)
	default:
		_ = vault.Rename(to, from, false)
	}
	return updated, err
}

// secretUsers lists the servers, conns, keys and VPNs whose references point
// at the vault secret name.
func secretUsers(st *store.State, name string) []string {
	return walkSecretRefs(st, name, "")
}

// renameSecretRefs points every reference to secret:from at secret:to and
// returns what it changed.
func renameSecretRefs(st *store.State, from, to string) []string {
	return walkSecretRefs(st, from, to)
}

// walkSecretRefs finds every reference to secret:name in the state - the
// password, sudo and passphrase refs, a server's environment variables, a
// conn URL's options (?ca=secret:NAME) and a VPN's key, preshared key and
// config - and, when rename is set, points it at secret:rename.
func walkSecretRefs(st *store.State, name, rename string) []string {
	ref := "secret:" + name
	now := time.Now().UTC()
	users := map[string]bool{}
	visit := func(user string, touch func(), ps ...*string) {
		hit := false
		for _, p := range ps {
			if *p == ref {
				hit = true
				if rename != "" {
					*p = "secret:" + rename
				}
			}
		}
		if hit {
			users[user] = true
			if rename != "" && touch != nil {
				touch()
			}
		}
	}
	for _, h := range st.Hosts {
		ps := []*string{&h.PasswordRef, &h.SudoRef}
		env := make([]string, 0, len(h.Env))
		for k := range h.Env {
			env = append(env, k)
		}
		sort.Strings(env)
		vals := make([]string, len(env))
		for i, k := range env {
			vals[i] = h.Env[k]
			ps = append(ps, &vals[i])
		}
		visit("host "+h.Name, func() { h.UpdatedAt = now }, ps...)
		for i, k := range env {
			h.Env[k] = vals[i]
		}
	}
	for _, c := range st.Conns {
		visit("conn "+c.Name, func() { c.UpdatedAt = now }, &c.PasswordRef)
		// a URL option such as a registry's ?ca=secret:NAME
		if u, hit := renameURLSecretRefs(c.URL, name, rename); hit {
			users["conn "+c.Name] = true
			if rename != "" {
				c.URL, c.UpdatedAt = u, now
			}
		}
	}
	for _, k := range st.Keys {
		visit("key "+k.Name, nil, &k.PassphraseRef)
	}
	for _, v := range st.Vpns {
		visit("vpn "+v.Name, func() { v.UpdatedAt = now }, &v.KeyRef, &v.PSKRef, &v.ConfigRef)
	}
	list := make([]string, 0, len(users))
	for u := range users {
		list = append(list, u)
	}
	sort.Strings(list)
	return list
}

// urlSecretRef is a conn URL option whose value is secret:NAME, such as
// the CA certificate of a registry: ?ca=secret:NAME.
type urlSecretRef struct{ Option, Name string }

// urlSecretRefs lists the options of a conn URL that name a vault secret,
// in the order they are written.
func urlSecretRefs(rawURL string) []urlSecretRef {
	var refs []urlSecretRef
	mapURLSecretRefs(rawURL, func(opt, name string) string {
		refs = append(refs, urlSecretRef{opt, name})
		return name
	})
	return refs
}

// renameURLSecretRefs reports whether an option of the URL says
// secret:from and, when to is set, returns the URL with those options
// saying secret:to. The rest of the URL stays as it was written.
func renameURLSecretRefs(rawURL, from, to string) (string, bool) {
	hit := false
	u := mapURLSecretRefs(rawURL, func(_, name string) string {
		if name != from {
			return name
		}
		hit = true
		if to == "" {
			return name
		}
		return to
	})
	return u, hit
}

// mapURLSecretRefs calls fn for every query option of the URL whose value
// is secret:NAME and writes back the name fn returns. It splits the URL the
// way net/url does (the query runs from the first ? to the #) and edits
// the text in place, so options it does not change keep their order and
// their escaping. Secret names need no escaping (validName).
func mapURLSecretRefs(rawURL string, fn func(opt, name string) string) string {
	rest, frag, hasFrag := strings.Cut(rawURL, "#")
	head, query, ok := strings.Cut(rest, "?")
	if !ok || query == "" {
		return rawURL
	}
	parts := strings.Split(query, "&")
	changed := false
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		val, err := url.QueryUnescape(v)
		if err != nil {
			continue
		}
		name, ok := strings.CutPrefix(val, "secret:")
		if !ok || name == "" {
			continue
		}
		opt, err := url.QueryUnescape(k)
		if err != nil {
			opt = k
		}
		if n := fn(opt, name); n != name {
			parts[i] = k + "=secret:" + n
			changed = true
		}
	}
	if !changed {
		return rawURL
	}
	u := head + "?" + strings.Join(parts, "&")
	if hasFrag {
		u += "#" + frag
	}
	return u
}

func secretKeychainCmd() *cobra.Command {
	var off bool
	c := &cobra.Command{
		Use:   "keychain",
		Short: "Keep the vault key in the OS keychain instead of vault.key",
		Long: `Moves the vault's key out of the vault.key file into the operating system's
keychain, so a copy of ` + "~/.komando" + ` (a backup, a synced folder) no longer opens
the vault. Nothing is re-encrypted: it is the same key, kept elsewhere.
--off moves it back into vault.key, which needs --yes.`,
		Example: "  komando secret keychain\n  komando secret keychain --off --yes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if g.dryRun {
				tool, err := vault.KeychainTool()
				res := map[string]any{"dry_run": true, "would": map[bool]string{false: "move the vault key into the keychain", true: "move the vault key back into vault.key"}[off]}
				if err != nil {
					res["problem"] = err.Error()
				} else {
					res["keychain"] = tool
				}
				out.P.Print("secret.keychain", res, nil)
				return nil
			}
			if off {
				if err := guardSafety("moving the vault key out of the keychain into a file"); err != nil {
					return err
				}
				err := vault.KeyToFile()
				audit(nil, "secret.keychain", nil, "", err == nil, map[string]any{"key": "file"})
				if err != nil {
					return out.Errf(out.ExitRemote, "KEYCHAIN_FAILED", "unlock the keychain and try again", "%v", err)
				}
				out.P.Print("secret.keychain", map[string]any{"key": "vault.key"}, nil)
				return nil
			}
			tool, err := vault.KeyToKeychain()
			audit(nil, "secret.keychain", nil, "", err == nil, map[string]any{"key": "keychain"})
			if err != nil {
				return out.Errf(out.ExitRemote, "KEYCHAIN_FAILED", "the vault still uses vault.key; fix the keychain and try again", "%v", err)
			}
			out.P.Print("secret.keychain", map[string]any{"key": "keychain", "keychain": tool, "vault_key_file": "removed"}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&off, "off", false, "move the key back into vault.key (needs --yes)")
	return c
}

// secretInUse names the command that points the first user elsewhere.
func secretInUse(name string, users []string) error {
	kind, who, _ := strings.Cut(users[0], " ")
	hint := map[string]string{
		"host": "komando host edit " + who + " --password-ref ... (or --sudo-ref ..., --env ...)",
		"conn": "komando conn edit " + who + " --password-ref ...",
		"key":  "komando key edit " + who + " --passphrase-ref ...",
		"vpn":  "komando vpn edit " + who + " ...",
	}[kind]
	return out.Errf(out.ExitConflict, "SECRET_IN_USE", "point them at another secret first, e.g. `"+hint+"`, or rename it with `komando secret mv`",
		"secret %s is used by %s", name, strings.Join(users, ", "))
}
