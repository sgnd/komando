package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// passphraseResult is what `secret passphrase` did, or would do.
type passphraseResult struct {
	From      string   `json:"from"` // keyfile | passphrase | keychain; "none" when there was no vault
	To        string   `json:"to"`   // passphrase | keyfile
	Secrets   int      `json:"secrets"`
	DryRun    bool     `json:"dry_run,omitempty"`
	OpensNow  *bool    `json:"opens_now,omitempty"` // dry run: the current key opens every secret
	OldKey    string   `json:"old_key_removed,omitempty"`
	Warning   string   `json:"warning,omitempty"`
	Restart   []string `json:"restart"` // background komando processes that hold the old key
	NextSteps []string `json:"next_steps"`
}

func (r passphraseResult) Text() string {
	var b strings.Builder
	if r.DryRun {
		if r.From == r.To {
			fmt.Fprintf(&b, "Would re-encrypt %d secret%s under a new passphrase (KOMANDO_VAULT_PASS).\n", r.Secrets, plural(r.Secrets))
		} else {
			fmt.Fprintf(&b, "Would re-encrypt %d secret%s, and the vault's key would go from %s to %s.\n", r.Secrets, plural(r.Secrets), keyWhere(r.From), keyWhere(r.To))
		}
		if r.OpensNow != nil && !*r.OpensNow {
			b.WriteString("The current key does not open the vault: for a passphrase vault, komando asks for the current passphrase.\n")
		}
	} else {
		fmt.Fprintf(&b, "Re-encrypted %d secret%s, and the vault's key is now %s.\n", r.Secrets, plural(r.Secrets), keyWhere(r.To))
		if r.OldKey != "" {
			fmt.Fprintf(&b, "The old key was removed (%s).\n", map[string]string{"store.key": "store.key", "keychain": "from the keychain"}[r.OldKey])
		}
	}
	if r.Warning != "" {
		b.WriteString("warning: " + r.Warning + "\n")
	}
	if len(r.Restart) > 0 {
		b.WriteString("Running with the old key: " + strings.Join(r.Restart, ", ") + ".\n")
	}
	if len(r.NextSteps) > 0 {
		b.WriteString(map[bool]string{true: "Then:\n", false: "Now:\n"}[r.DryRun])
		for _, s := range r.NextSteps {
			b.WriteString("  - " + s + "\n")
		}
	}
	return b.String()
}

func keyWhere(mode string) string {
	switch mode {
	case "passphrase":
		return "a passphrase (KOMANDO_VAULT_PASS)"
	case "keychain":
		return "a key in the OS keychain"
	case "keyfile":
		return "a random key in " + store.Path("store.key")
	}
	return "nothing (no vault yet)"
}

// newPassphraseProblem says why a passphrase would make a poor vault key,
// or "". It never shows the passphrase.
func newPassphraseProblem(p string) string {
	switch n := utf8.RuneCountInString(p); {
	case n == 0:
		return "the passphrase is empty"
	case n < vault.MinPassphrase:
		return fmt.Sprintf("the passphrase has %d characters; it needs %d or more (NIST SP 800-63B)", n, vault.MinPassphrase)
	case strings.TrimSpace(p) != p:
		// an export line in a shell profile or a launch agent easily loses it
		return "the passphrase starts or ends with a space"
	case strings.ContainsFunc(p, unicode.IsControl):
		return "the passphrase holds control characters"
	}
	return ""
}

// runningServes lists komando's background processes that opened the
// vault with the key they were started with: tunnels and VPN sessions.
func runningServes() []string {
	st, err := loadState()
	if err != nil {
		return nil
	}
	var r []string
	for id, t := range st.Tunnels {
		if tunnelAlive(t) {
			r = append(r, "tunnel "+id)
		}
	}
	for name, s := range st.Sessions {
		if netx.SessionAlive(s) {
			r = append(r, "vpn "+name)
		}
	}
	sort.Strings(r)
	return r
}

func secretPassphraseCmd() *cobra.Command {
	var off bool
	c := &cobra.Command{
		Use:   "passphrase",
		Short: "Change the vault passphrase and encrypt the secrets again",
		Long: `Re-encrypts every secret in the vault under a new passphrase, so you can change
KOMANDO_VAULT_PASS without losing your secrets. A vault whose key is in
store.key or in the OS keychain gets a passphrase this way, and the old key is
removed once the new vault is saved and read back.

The vault is opened the usual way: with KOMANDO_VAULT_PASS, store.key or the
keychain. When KOMANDO_VAULT_PASS does not open a passphrase vault (you changed
it already, say), komando asks for the current passphrase. Then it asks for
the new one twice, hidden; it needs 15 or more characters. Every secret is
decrypted before anything is written: if one cannot be, nothing changes.

Afterwards, put the new passphrase in KOMANDO_VAULT_PASS wherever you set it
(your shell profile, a password manager, a launch agent), and restart any
background tunnel or VPN session komando runs: they still hold the old key.

--off goes back to a new random key in store.key (needs --yes): a copy of
` + "~/.komando" + ` then opens the vault again. ` + "`komando secret keychain`" + ` can move that
key into the OS keychain.

Only a person at a terminal can run it: an AI agent that chose the passphrase,
or put the key back in store.key, could open the vault on its own. Anyone can
preview it with --dry-run.`,
		Example: "  komando secret passphrase               # asks for the new passphrase twice, hidden\n  komando secret passphrase --dry-run\n  komando secret passphrase --off --yes   # back to a random key in store.key",
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			return runSecretPassphrase(cl, off)
		}),
	}
	c.Flags().BoolVar(&off, "off", false, "back to a random key in store.key (needs --yes)")
	return c
}

// passphraseNextSteps is what a person does after the vault's key changed.
func passphraseNextSteps(to string) []string {
	if to == "keyfile" {
		return []string{
			"remove KOMANDO_VAULT_PASS wherever you set it (your shell profile, a launch agent): the vault does not use it any more",
			"`komando secret keychain` moves the new key into the OS keychain, so a copy of " + store.Home() + " does not open the vault",
		}
	}
	return []string{
		"put the new passphrase in KOMANDO_VAULT_PASS wherever you set it (your shell profile, a password manager, a launch agent); until then komando cannot open the vault",
		"restart background tunnels and VPN sessions komando runs (`komando tunnel list`, `komando vpn status`): they still hold the old key",
	}
}

func runSecretPassphrase(cl *call, off bool) error {
	if cl.isAgent() || !cl.interactive() {
		// a dry run is never blocked: it says what would change, and that
		// the real run needs the user (policyStop records it)
		if err := cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"ask the user to run `komando secret passphrase` in their own terminal",
			"only a person at a terminal can change the vault's key: an AI agent that chose the passphrase, or put the key in store.key, could open the vault on its own")); err != nil {
			return err
		}
	}
	res, err := passphrasePlan(off)
	if err != nil {
		return err
	}
	if cl.flags.dryRun {
		res.DryRun = true
		opens := vault.Opens("") == nil
		res.OpensNow = &opens
		cl.out.Print("secret.passphrase", res, nil)
		return nil
	}
	// the current key first, so nobody types a new passphrase twice for a
	// vault that will not open
	old, err := currentPassphrase(cl, res.From)
	if err != nil {
		return err
	}
	newPass := ""
	if off {
		err = guardSafety(cl, "moving the store's key from a passphrase into store.key next to the store")
	} else {
		newPass, err = askNewPassphrase(cl)
	}
	if err != nil {
		return err
	}
	kc, err := vault.ChangeKey(cl.storeWrite(), old, newPass)
	audit(cl, nil, "secret.passphrase", nil, "", err == nil, map[string]any{"from": res.From, "to": res.To, "secrets": kc.Secrets})
	switch {
	case errors.Is(err, vault.ErrWrongKey): // changed by another komando meanwhile
		return out.Errf(out.ExitConflict, "VAULT_CHANGED", "run it again", "%v; nothing was changed", err)
	case err != nil:
		return err
	}
	res.Secrets, res.OldKey, res.Warning = kc.Secrets, kc.Removed, kc.Left
	cl.out.Print("secret.passphrase", res, nil)
	return nil
}

// passphrasePlan says what `secret passphrase` will do to the vault, or why
// --off has nothing to do.
func passphrasePlan(off bool) (passphraseResult, error) {
	res := passphraseResult{To: "passphrase", Restart: []string{}, NextSteps: []string{}}
	s, err := vault.Check()
	if err != nil {
		return res, err
	}
	// a passphrase that does not open the store (changed already) is asked
	// for next (currentPassphrase); ChangeKey counts the secrets then
	list, err := vault.List()
	if err != nil && !(s.Mode == "passphrase" && errors.Is(err, sealdb.ErrWrongKey)) {
		return res, err
	}
	res.From, res.Secrets = s.Mode, len(list)
	if s.NoVaultYet {
		res.From = "none"
	}
	if off {
		res.To = "keyfile"
		if res.From != "passphrase" {
			hint := map[string]string{
				"keyfile":  "its key is in " + store.Path("store.key") + " already",
				"keychain": "its key is in the OS keychain; `komando secret keychain --off --yes` moves it into store.key",
				"none":     "there is no store yet; without KOMANDO_VAULT_PASS the first change keeps its key in the OS keychain, or in store.key where the keychain cannot keep it",
			}[res.From]
			return res, out.Errf(out.ExitUsage, "NO_PASSPHRASE", hint, "the vault has no passphrase to take away")
		}
	}
	res.NextSteps = passphraseNextSteps(res.To)
	if res.To == "passphrase" {
		res.Restart = orEmpty(runningServes())
	}
	return res, nil
}

// currentPassphrase checks that the vault opens with the key komando has.
// For a passphrase vault that KOMANDO_VAULT_PASS does not open (not set,
// or changed already), it asks the person for the current passphrase and
// returns it; otherwise "".
func currentPassphrase(cl *call, from string) (string, error) {
	err := vault.Opens("")
	if err == nil {
		return "", nil
	}
	if from != "passphrase" || (vault.Passphrase() != "" && !errors.Is(err, vault.ErrWrongKey)) {
		return "", out.Errf(out.ExitError, "VAULT_LOCKED", "fix that, then run it again", "%v; nothing was changed", err)
	}
	if vault.Passphrase() == "" {
		fmt.Fprintln(cl.out.Err, "KOMANDO_VAULT_PASS is not set.")
	} else {
		fmt.Fprintln(cl.out.Err, "KOMANDO_VAULT_PASS does not open the vault (did you change it already?).")
	}
	old, err := readHidden(cl, "Current vault passphrase (hidden): ")
	if err != nil {
		return "", err
	}
	if err := vault.Opens(old); err != nil {
		if errors.Is(err, vault.ErrWrongKey) {
			return "", out.Errf(out.ExitUsage, "WRONG_PASSPHRASE", "run it again and type the passphrase the vault has now",
				"that passphrase does not open the vault; nothing was changed")
		}
		return "", err
	}
	return old, nil
}

// askNewPassphrase asks for the new passphrase twice, hidden.
func askNewPassphrase(cl *call) (string, error) {
	fmt.Fprintf(cl.out.Err, "Choose a new vault passphrase: %d or more characters (random words work well).\n", vault.MinPassphrase)
	p1, err := readHidden(cl, "New vault passphrase (hidden): ")
	if err != nil {
		return "", err
	}
	if why := newPassphraseProblem(p1); why != "" {
		return "", out.Errf(out.ExitUsage, "WEAK_PASSPHRASE", "run it again with another passphrase", "%s; nothing was changed", why)
	}
	p2, err := readHidden(cl, "Type it again (hidden): ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", out.Errf(out.ExitUsage, "PASSPHRASE_MISMATCH", "run it again", "the two passphrases you typed differ; nothing was changed")
	}
	return p1, nil
}
