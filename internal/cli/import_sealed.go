package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealfile"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando import komando FILE` on a sealed file (export --sealed): a
// person types its passphrase, then the import takes the export document
// inside with the same limits as any export file, and puts the file's
// secrets into the vault: a new name is added, and a name that is here
// with another value is replaced only with --overwrite and the person's
// yes.

// sealedKey is a private key a sealed file adds, kept in the store.
type sealedKey struct {
	key     *store.Key
	private []byte
}

func importSealed(cl *call, path string, b []byte) (*importPlan, error) {
	h, err := sealfile.ReadHeader(b)
	if err != nil {
		return nil, sealedFileErr(path, err)
	}
	if h.Mode == sealfile.ModeRecipient {
		return nil, out.Errf(out.ExitUsage, "SEALED_FILE_UNSUPPORTED", "on the old computer, make a file for this one with `komando export --sealed --to FILE`",
			"%s is sealed for the iPhone app: only the phone whose key it was sealed to opens it; nothing was imported", path)
	}
	if cl.isAgent() || !cl.interactive() {
		e := out.Errf(out.ExitPolicy, "NEEDS_PERSON", "ask the user to run `"+commandLine(cl)+"` in their own terminal; never ask for the passphrase in the chat",
			"%s is sealed: only a person at a terminal can open it with its passphrase", path)
		if err := cl.policyStop(e); err != nil {
			return nil, err
		}
		p := newPlan() // a dry run: what is inside shows only once it is open
		p.Notes = append(p.Notes, path+": sealed; what it holds shows when a person opens it with its passphrase")
		return p, nil
	}
	pass, err := readPassword(cl, "Passphrase of "+filepath.Base(path)+" (hidden): ")
	if err != nil {
		return nil, err
	}
	raw, _, err := sealfile.OpenPassphrase(b, pass)
	if err != nil {
		return nil, sealedFileErr(path, err)
	}
	var c sealedContent
	if err := json.Unmarshal(raw, &c); err != nil || c.Format != exportFormat {
		return nil, sealedFileErr(path, sealfile.ErrUnsupported)
	}
	p := newPlan()
	if err := sealedSecrets(cl, p, c.SecretValues); err != nil {
		return nil, err
	}
	var missing []string
	for _, n := range c.Secrets {
		if _, ok := c.SecretValues[n]; !ok {
			missing = append(missing, n)
		}
	}
	np := planFromExport(cl, c.exportFile)
	np.SealedSecrets, np.Notes = p.SealedSecrets, append(p.Notes, np.Notes...)
	if len(missing) > 0 {
		np.Notes = append(np.Notes, "secrets the file does not hold (set them with `komando secret set NAME`): "+strings.Join(missing, ", "))
	}
	return np, sealedKeys(cl, np, c)
}

// sealedFileErr is the error for a sealed file that does not open.
func sealedFileErr(path string, err error) error {
	switch {
	case errors.Is(err, sealfile.ErrWrongPassphrase):
		return out.Errf(out.ExitUsage, "WRONG_PASSPHRASE", "run it again and type the passphrase the file was sealed with",
			"that passphrase does not open %s, or the file was changed after it was sealed; nothing was imported", path)
	case errors.Is(err, sealfile.ErrUnsupported):
		return out.Errf(out.ExitUsage, "SEALED_FILE_UNSUPPORTED", "update komando (`komando update`), then import it again",
			"%s is a sealed file of a version or kind this komando does not read; nothing was imported", path)
	}
	return out.Errf(out.ExitUsage, "SEALED_FILE_INVALID", "copy the file again whole, or make it again with `komando export --sealed --to FILE`",
		"%s is damaged or cut short: komando cannot read it as a sealed file; nothing was imported", path)
}

// sealedSecrets decides what happens to each secret of the file: a name
// that is not here is added, the same value here is left as it is, and
// another value here is kept unless --overwrite and the person says yes.
// It sets carriedSecrets.
func sealedSecrets(cl *call, p *importPlan, vals map[string]string) error {
	carried, differ := map[string]bool{}, []string{}
	p.SealedSecrets = map[string]string{}
	for _, n := range slices.Sorted(maps.Keys(vals)) {
		v := vals[n]
		if validName("secret", n) != nil || reservedSecret(n) != nil || v == "" || out.HasHidden(v) {
			p.Notes = append(p.Notes, "secret "+n+": left out (komando does not take this name or value)")
			continue
		}
		have, err := vault.Get(n)
		switch {
		case errors.Is(err, vault.ErrNotFound):
			p.SealedSecrets[n], carried[n] = v, true
		case err != nil:
			return err
		case have == v:
			carried[n] = true
		case cl.importOverwrite:
			differ = append(differ, n)
		default:
			p.Notes = append(p.Notes, "secret "+n+": kept the value here, which differs from the file's (--overwrite replaces it after you agree)")
		}
	}
	if len(differ) > 0 {
		switch {
		case cl.flags.dryRun:
			p.Notes = append(p.Notes, "differ here, and the import asks before it replaces them: "+strings.Join(differ, ", "))
		case confirmYes(cl, fmt.Sprintf("This replaces %s here with the file's: %s. Continue?", countOf(len(differ), "secret"), strings.Join(differ, ", "))):
			for _, n := range differ {
				p.SealedSecrets[n], carried[n] = vals[n], true
				p.Notes = append(p.Notes, "secret "+n+": replaced with the file's value")
			}
		default:
			p.Notes = append(p.Notes, "kept the values here (not replaced): "+strings.Join(differ, ", "))
		}
	}
	cl.carriedSecrets = carried
	return nil
}

// sealedKeys plans the private keys of the file. A key whose name is here
// already is left out: the servers that name it use the one here.
func sealedKeys(cl *call, p *importPlan, c sealedContent) error {
	if len(c.KeyTexts) == 0 {
		return nil
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	for _, n := range slices.Sorted(maps.Keys(c.KeyTexts)) {
		if validName("key", n) != nil {
			p.Notes = append(p.Notes, "key "+n+": left out (komando does not take this name)")
			continue
		}
		if _, ok := st.Keys[n]; ok {
			p.Notes = append(p.Notes, "key "+n+": a key with this name is here already, so the file's was left out")
			continue
		}
		text := []byte(c.KeyTexts[n])
		var pub ssh.PublicKey
		signer, err := ssh.ParsePrivateKey(text)
		var pme *ssh.PassphraseMissingError
		switch {
		case err == nil:
			pub = signer.PublicKey()
		case errors.As(err, &pme) && pme.PublicKey != nil:
			pub = pme.PublicKey
		default:
			p.Notes = append(p.Notes, "key "+n+": left out (komando cannot read it)")
			continue
		}
		ref := c.KeyPassphraseRefs[n]
		if note := dropForeignRef(cl, "key "+n, "passphrase_ref", &ref); note != "" {
			p.Notes = append(p.Notes, note)
		}
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		k := &store.Key{Name: n, Type: pub.Type(), PublicKey: line, Fingerprint: ssh.FingerprintSHA256(pub), PassphraseRef: ref, Managed: true, CreatedAt: time.Now().UTC()}
		p.SealedKeys = append(p.SealedKeys, sealedKey{k, text})
	}
	return nil
}

// sealedKeysInto puts the keys a sealed file adds into st (not saved), so
// the servers that use them keep them.
func sealedKeysInto(st *store.State, p *importPlan) {
	for _, k := range p.SealedKeys {
		if _, ok := st.Keys[k.key.Name]; !ok {
			st.Keys[k.key.Name] = k.key
		}
	}
}

// sealedNames adds the secrets a sealed file stores to the import's list
// (secrets) and to the values the import stores; keys are the names of
// the keys it adds.
func (p *importPlan) sealedNames(secrets []string) (all, keys []string) {
	if len(p.SealedSecrets) == 0 && len(p.SealedKeys) == 0 {
		return secrets, nil // not a sealed file: as it was
	}
	for n, v := range p.SealedSecrets {
		p.Secrets[n] = v
		secrets = append(secrets, n)
	}
	for _, k := range p.SealedKeys {
		keys = append(keys, k.key.Name)
	}
	return append([]string{}, dedupe(secrets)...), keys // sorted, never null
}

// putSealedKeys keeps the private keys of a sealed file in the store and
// adds them to s.
func putSealedKeys(s *store.State, p *importPlan) error {
	for _, k := range p.SealedKeys {
		if _, ok := s.Keys[k.key.Name]; ok {
			continue
		}
		kept, err := store.WriteManagedKey(k.key.Name, k.private, []byte(k.key.PublicKey+"\n"))
		if err != nil {
			return err
		}
		k.key.Path = kept
		s.Keys[k.key.Name] = k.key
	}
	return nil
}
