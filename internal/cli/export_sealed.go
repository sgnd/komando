package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealfile"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// A sealed export (docs/design/sealed-file.md) is the export document with
// the secret values its records use, and with --with-keys the private
// keys, in one sealed file: --sealed opens with a passphrase on any
// computer, --for-phone only with the key the iPhone app made for it.
// Only a person at a terminal makes one.

// exportSealOpts are the export flags that seal the file.
type exportSealOpts struct{ sealed, forPhone, withKeys bool }

func (o exportSealOpts) on() bool { return o.sealed || o.forPhone }

func (o exportSealOpts) mode() string {
	if o.forPhone {
		return sealfile.ModeRecipient
	}
	return sealfile.ModePassphrase
}

// check refuses flags that do not go together, before anything is read.
func (o exportSealOpts) check(to string) error {
	switch {
	case o.sealed && o.forPhone:
		return out.Errf(out.ExitUsage, "USAGE", "use --sealed for another computer (it opens with a passphrase) or --for-phone for the iPhone app",
			"--sealed and --for-phone seal one file two ways; give one of them")
	case o.withKeys && !o.on():
		return out.Errf(out.ExitUsage, "USAGE", "add --sealed or --for-phone, for example `komando export --sealed --with-keys --to move.kmdseal`",
			"--with-keys puts private keys in a sealed file only; an export without a seal never holds a key")
	case o.on() && (to == "" || to == "-"):
		flag := map[bool]string{true: "--for-phone", false: "--sealed"}[o.forPhone]
		return out.Errf(out.ExitUsage, "USAGE", "for example `komando export "+flag+" --to move.kmdseal`",
			"%s writes a file: give it with --to FILE", flag)
	}
	return nil
}

// sealedContent is what a sealed file holds: the export document, the
// values of the secrets its records use, and the private keys the person
// chose (OpenSSH text, as komando keeps them).
type sealedContent struct {
	exportFile
	SecretValues map[string]string `json:"secrets"`
	KeyTexts     map[string]string `json:"keys"`
	// KeyPassphraseRefs: the passphrase reference of a key in keys that has
	// one (its secret is in secrets)
	KeyPassphraseRefs map[string]string `json:"key_passphrase_refs,omitempty"`
}

func runExportSealed(st *store.State, f exportFile, o exportSealOpts, to string, overwrite bool) error {
	if _, err := os.Stat(to); err == nil && !overwrite {
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another file or pass --overwrite", "%s already exists", to)
	}
	if isAgent() || !interactive() {
		// a dry run is never blocked: it says what would be sealed, and
		// that the real run needs a person (policyStop records it)
		if err := policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON",
			"ask the user to run `"+commandLine()+"` in their own terminal; never ask for the passphrase in the chat",
			"only a person at a terminal can make a sealed file: it holds the passwords")); err != nil {
			return err
		}
	}
	res := exportResult{File: to, Hosts: len(f.Hosts), Conns: len(f.Conns), Vpns: len(f.Vpns), Recipes: len(f.Recipes),
		DenyRules: len(f.DenyRules), Settings: len(f.Settings) > 0, Sealed: o.mode(), SecretsNeeded: []string{}, KeysNeeded: []string{}}
	if g.dryRun {
		res.DryRun, res.SecretsInFile = true, []string{}
		for _, n := range f.Secrets { // which are there, never their values
			if _, err := vault.Get(n); errors.Is(err, vault.ErrNotFound) {
				res.SecretsNeeded = append(res.SecretsNeeded, n)
			} else {
				res.SecretsInFile = append(res.SecretsInFile, n)
			}
		}
		if o.withKeys {
			res.KeysInFile = f.Keys
		} else {
			res.KeysNeeded = f.Keys
		}
		out.P.Print("export", res, nil)
		return nil
	}
	c, err := sealContent(st, f, o.withKeys, &res)
	if err != nil {
		return err
	}
	content, err := json.Marshal(c)
	if err != nil {
		return err
	}
	made := sealfile.Made{By: "komando " + Version}
	var file []byte
	if o.forPhone {
		pub, err := askPhoneKey()
		if err != nil {
			return err
		}
		res.PhoneKeyID = sealfile.KeyID(pub)
		file, err = sealfile.SealRecipient(content, pub, made)
		if err != nil {
			return err
		}
	} else {
		pass, err := askFilePassphrase()
		if err != nil {
			return err
		}
		if file, err = sealfile.SealPassphrase(content, pass, made); err != nil {
			return err
		}
	}
	if err := exportTarget(to, overwrite); err != nil {
		return err
	}
	if err := writeExport(to, file, overwrite); err != nil {
		return err
	}
	res.CheckPhrase = sealfile.CheckPhrase(file)
	audit(nil, "export.sealed", nil, "", true, map[string]any{"file": to, "mode": res.Sealed, "hosts": res.Hosts, "conns": res.Conns,
		"vpns": res.Vpns, "recipes": res.Recipes, "secrets": len(res.SecretsInFile), "keys": len(res.KeysInFile)})
	if !o.forPhone {
		sayNext("komando import komando " + to + " (on the other computer; it asks for the passphrase)")
	}
	out.P.Print("export", res, nil)
	return nil
}

// sealContent reads the secret values (and with withKeys the private keys)
// the export's records use. A secret that is not in the vault and a key
// that cannot travel are listed in res as still needed.
func sealContent(st *store.State, f exportFile, withKeys bool, res *exportResult) (sealedContent, error) {
	c := sealedContent{exportFile: f, SecretValues: map[string]string{}, KeyTexts: map[string]string{}}
	for _, n := range f.Secrets {
		v, err := vault.Get(n)
		if errors.Is(err, vault.ErrNotFound) {
			res.SecretsNeeded = append(res.SecretsNeeded, n)
			continue
		}
		if err != nil {
			return c, err
		}
		c.SecretValues[n] = v
	}
	left := map[string]bool{}
	for _, n := range f.Keys {
		k := st.Keys[n]
		if !withKeys {
			left[n] = true
			continue
		}
		b, err := store.ReadPrivateKey(k)
		if err != nil {
			return c, out.Errf(out.ExitError, "KEY_FAILED", "check the key with `komando key show "+n+"`, or leave out --with-keys",
				"could not read key %s: %v; nothing was written", n, errText(err))
		}
		var pme *ssh.PassphraseMissingError
		if _, err := ssh.ParsePrivateKey(b); err != nil && !errors.As(err, &pme) {
			left[n] = true // a security key (FIDO2) stays on its device
			continue
		}
		c.KeyTexts[n] = string(b)
		if k.PassphraseRef != "" {
			if c.KeyPassphraseRefs == nil {
				c.KeyPassphraseRefs = map[string]string{}
			}
			c.KeyPassphraseRefs[n] = k.PassphraseRef
		}
	}
	res.SecretsInFile = slices.Sorted(maps.Keys(c.SecretValues))
	res.KeysInFile = slices.Sorted(maps.Keys(c.KeyTexts))
	res.KeysNeeded, res.KeyFiles, res.KeysSealed = exportKeys(st, left)
	return c, nil
}

// askFilePassphrase asks for the sealed file's passphrase twice, hidden.
func askFilePassphrase() (string, error) {
	fmt.Fprintf(os.Stderr, "Choose a passphrase for the file: %d or more characters (random words work).\n", vault.MinPassphrase)
	p1, err := readPassword("Passphrase (hidden): ")
	if err != nil {
		return "", err
	}
	if why := newPassphraseProblem(p1); why != "" {
		return "", out.Errf(out.ExitUsage, "WEAK_PASSPHRASE", "run it again with another passphrase", "%s; nothing was written", why)
	}
	p2, err := readPassword("Type it again (hidden): ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", out.Errf(out.ExitUsage, "PASSPHRASE_MISMATCH", "run it again", "the two passphrases you typed differ; nothing was written")
	}
	return p1, nil
}

// askPhoneKey asks for the key the iPhone app made for this export (its
// file, or the key as text) and for the key check the phone shows, and
// returns the key only when the two match: a key file swapped on the way
// does not match what the phone shows.
func askPhoneKey() ([]byte, error) {
	fmt.Fprintln(os.Stderr, "The iPhone app makes a key for this export: a key file and a key check.")
	ans, err := readPhoneAnswer("Key file from the phone (or the key as text): ", false)
	if err != nil {
		return nil, err
	}
	pub, err := readPhoneKey(strings.TrimSpace(ans))
	if err != nil {
		return nil, err
	}
	check, err := readPhoneAnswer("Key check the phone shows: ", false)
	if err != nil {
		return nil, err
	}
	if !sameKeyCheck(check, pub) {
		return nil, out.Errf(out.ExitUsage, "PHONE_KEY_INVALID", "check that the key file came from the phone, then run `komando export --for-phone --to FILE` again and type the key check it shows",
			"the key does not match the key check the phone shows; nothing was written")
	}
	return pub, nil
}

// readPhoneAnswer reads an answer to askPhoneKey; tests stand in for the
// terminal.
var readPhoneAnswer = readAnswer

// readPhoneKey reads the phone's X25519 public key from a file, or from
// the answer itself: 32 bytes, as base64 or hex.
func readPhoneKey(ans string) ([]byte, error) {
	bad := func(why string) error {
		return out.Errf(out.ExitUsage, "PHONE_KEY_INVALID", "run `komando export --for-phone --to FILE` again and give the key file the phone shared, or paste the key as it shows it",
			"komando cannot read the phone's key: %s; nothing was written", why)
	}
	if ans == "" {
		return nil, bad("no key was given")
	}
	b := []byte(ans)
	if fi, err := os.Stat(expandHome(ans)); err == nil && fi.Mode().IsRegular() {
		if fi.Size() > 4096 {
			return nil, bad(ans + " is too big to be a key")
		}
		if b, err = os.ReadFile(expandHome(ans)); err != nil {
			return nil, bad(errText(err))
		}
	}
	if len(b) == 32 {
		return b, nil
	}
	t := strings.Join(strings.Fields(string(b)), "")
	if k, err := hex.DecodeString(t); err == nil && len(k) == 32 {
		return k, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(t); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, bad("it is not a 32-byte key (base64 or hex)")
}

// sameKeyCheck: the typed key check is the key's key_id, whatever spaces,
// dashes or case the person typed it with.
func sameKeyCheck(typed string, pub []byte) bool {
	t := strings.ToLower(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(typed)))
	return t == sealfile.KeyID(pub)
}

// sealedText is the -o text of a sealed export.
func (r exportResult) sealedText() string {
	var b strings.Builder
	var what []string
	for _, c := range []struct {
		n    int
		word string
	}{{r.Hosts, "server"}, {r.Conns, "conn"}, {r.Vpns, "VPN"}, {r.Recipes, "recipe"}} {
		if c.n > 0 {
			what = append(what, countOf(c.n, c.word))
		}
	}
	what = append(what, countOf(len(r.SecretsInFile), "secret"))
	if len(r.KeysInFile) > 0 {
		what = append(what, countOf(len(r.KeysInFile), "key"))
	}
	how := map[string]string{sealfile.ModePassphrase: "opens with its passphrase", sealfile.ModeRecipient: "opens only on the phone"}[r.Sealed]
	if r.DryRun {
		fmt.Fprintf(&b, "would seal %s into %s (it %s)\n", strings.Join(what, ", "), r.File, how)
	} else {
		fmt.Fprintf(&b, "sealed %s into %s (it %s)\n", strings.Join(what, ", "), r.File, how)
	}
	if len(r.CheckPhrase) > 0 {
		fmt.Fprintf(&b, "check phrase: %s\n", strings.Join(r.CheckPhrase, " "))
		if r.Sealed == sealfile.ModeRecipient {
			b.WriteString("the phone shows the same words for the file it got: if they differ, do not use it\n")
		}
	}
	if len(r.SecretsNeeded) > 0 {
		b.WriteString("not in the vault, so not in the file: " + strings.Join(r.SecretsNeeded, ", ") + "\n")
	}
	if len(r.KeysNeeded) > 0 {
		b.WriteString("keys not in the file (--with-keys adds the ones that can travel): " + strings.Join(r.KeysNeeded, ", ") + "\n")
	}
	return b.String()
}
