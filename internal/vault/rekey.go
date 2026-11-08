package vault

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/store"
)

// Changing the vault's key (`komando secret passphrase`): a new passphrase,
// a first passphrase for a vault whose key is in vault.key or the keychain,
// or a new random key in vault.key in place of a passphrase. Every secret is
// decrypted with the key the vault has now and sealed again with the new
// one, under a new salt. When one secret cannot be decrypted, nothing
// changes.

// ErrWrongKey matches the error of a key that does not open a secret in the
// vault (a wrong KOMANDO_VAULT_PASS, say).
var ErrWrongKey = errors.New("the key does not open the vault")

type wrongKeyError struct{ name string }

func (e *wrongKeyError) Error() string {
	return fmt.Sprintf("cannot decrypt secret %q (wrong KOMANDO_VAULT_PASS or vault.key?)", e.name)
}

func (e *wrongKeyError) Is(target error) bool { return target == ErrWrongKey }

// ErrShortPassphrase: a new passphrase must have MinPassphrase characters.
var ErrShortPassphrase = fmt.Errorf("a vault passphrase needs %d or more characters", MinPassphrase)

// ErrNoPassphrase: the vault has no passphrase to take away.
var ErrNoPassphrase = errors.New("the vault has no passphrase")

func newSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// openAll decrypts every secret with a. It stops at the first one that does
// not open, with an error that matches ErrWrongKey.
func (f *file) openAll(a cipher.AEAD) (map[string][]byte, error) {
	names := make([]string, 0, len(f.Entries))
	for name := range f.Entries {
		names = append(names, name)
	}
	sort.Strings(names) // the same secret is named every time
	plain := make(map[string][]byte, len(names))
	for _, name := range names {
		e := f.Entries[name]
		pt, err := a.Open(nil, e.Nonce, e.Data, []byte(name))
		if err != nil {
			wipe(plain)
			return nil, &wrongKeyError{name}
		}
		plain[name] = pt
	}
	return plain, nil
}

// sealAll seals each value again with a, bound to its name, under a new
// nonce. UpdatedAt stays: the values did not change.
func (f *file) sealAll(a cipher.AEAD, plain map[string][]byte) error {
	for name, pt := range plain {
		nonce := make([]byte, a.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		f.Entries[name].Nonce, f.Entries[name].Data = nonce, a.Seal(nil, nonce, pt, []byte(name))
	}
	return nil
}

func wipe(plain map[string][]byte) {
	for _, pt := range plain {
		clear(pt)
	}
}

// openWith decrypts every secret with the vault's current key: for a
// passphrase vault oldPass when it is not "", otherwise KOMANDO_VAULT_PASS;
// vault.key or the keychain for the others.
func (f *file) openWith(oldPass string) (map[string][]byte, error) {
	if len(f.Entries) == 0 {
		return map[string][]byte{}, nil // no key needed, and none is made
	}
	secret := []byte(oldPass)
	if f.Mode != "passphrase" || oldPass == "" {
		var err error
		if secret, err = f.key(); err != nil {
			return nil, err
		}
	}
	a, err := f.aeadFor(secret)
	if err != nil {
		return nil, err
	}
	return f.openAll(a)
}

// Opens checks, without changing anything, that every secret decrypts with
// the vault's current key (see ChangeKey for oldPass). An error that
// matches ErrWrongKey means one did not.
func Opens(oldPass string) error {
	f, err := load()
	if err != nil {
		return err
	}
	plain, err := f.openWith(oldPass)
	wipe(plain)
	return err
}

// KeyChange is what ChangeKey did.
type KeyChange struct {
	From    string `json:"from"`              // keyfile | passphrase | keychain; "" when there was no vault
	To      string `json:"to"`                // passphrase | keyfile
	Secrets int    `json:"secrets"`           // how many were sealed again
	Removed string `json:"removed,omitempty"` // the old key that was removed: vault.key | keychain
	Left    string `json:"left,omitempty"`    // the old key that could not be removed, and why
}

// ChangeKey seals every secret again under a new key: the passphrase
// newPass, or, when it is "", a new random key in vault.key. oldPass is the
// current passphrase of a passphrase vault when KOMANDO_VAULT_PASS does not
// hold it, otherwise "".
//
// It holds the vault lock throughout, so no secret saved meanwhile is lost.
// Every secret is decrypted before anything is written; when one cannot be,
// nothing changes. The new vault gets a new salt (and for a passphrase the
// scrypt cost PassphraseN), keeps each secret's UpdatedAt and is written
// atomically, then read back from disk and checked. Only then is the old
// vault.key or keychain item removed; when that fails, Left says so and the
// vault is changed all the same.
func ChangeKey(oldPass, newPass string) (KeyChange, error) {
	var res KeyChange
	if newPass != "" && utf8.RuneCountInString(newPass) < MinPassphrase {
		return res, ErrShortPassphrase
	}
	if store.DryRun {
		return res, store.ErrDryRun
	}
	unlock, err := store.Lock(lockName)
	if err != nil {
		return res, err
	}
	defer unlock()
	before, err := os.ReadFile(vaultPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	f, err := load()
	if err != nil {
		return res, err
	}
	if before != nil {
		res.From = f.Mode
	}
	if newPass == "" && res.From != "passphrase" {
		return res, ErrNoPassphrase
	}
	plain, err := f.openWith(oldPass)
	if err != nil {
		return res, err
	}
	defer wipe(plain)
	nf, newKey, err := f.resealed(newPass, plain)
	if err != nil {
		return res, err
	}
	if err := writeChecked(nf, newKey, plain, before); err != nil {
		return res, err
	}
	res.To, res.Secrets = nf.Mode, len(plain)
	if nf.Mode == "passphrase" {
		passMu.Lock()
		pass = newPass // the rest of this command opens the vault with it
		passMu.Unlock()
	}
	res.Removed, res.Left = removeOldKey(res.From)
	return res, nil
}

// resealed is a copy of the vault with a new salt and every value in plain
// sealed under a new key: the passphrase newPass, or when it is "" a new
// random key, which it returns.
func (f *file) resealed(newPass string, plain map[string][]byte) (*file, []byte, error) {
	salt, err := newSalt()
	if err != nil {
		return nil, nil, err
	}
	nf := &file{Version: f.Version, Salt: salt, Entries: make(map[string]*entry, len(f.Entries))}
	for name, e := range f.Entries {
		nf.Entries[name] = &entry{UpdatedAt: e.UpdatedAt}
	}
	var newKey []byte
	if newPass != "" {
		nf.Mode, nf.ScryptN, newKey = "passphrase", PassphraseN, []byte(newPass)
	} else {
		// a random key needs no more scrypt than a new key-file vault gets
		nf.Mode, newKey = "keyfile", make([]byte, keyLen)
		if _, err := rand.Read(newKey); err != nil {
			return nil, nil, err
		}
	}
	a, err := nf.aeadFor(newKey)
	if err != nil {
		return nil, nil, err
	}
	if err := nf.sealAll(a, plain); err != nil {
		return nil, nil, err
	}
	return nf, newKey, nil
}

// writeChecked writes the new vault (and for a key-file vault its key,
// first) and reads it back. When it does not read back, the old vault.json
// (before; nil when there was none) is put back.
func writeChecked(nf *file, newKey []byte, plain map[string][]byte, before []byte) error {
	kp := store.Path("vault.key")
	if nf.Mode == "keyfile" {
		// the key first: a vault.json that names a key file nobody wrote
		// would open nothing, while a key file the vault does not use yet
		// harms nothing
		if err := store.WriteFileAtomic(kp, newKey, 0o600); err != nil {
			return err
		}
	}
	putBack := func() error {
		var err error
		if before == nil {
			err = os.Remove(vaultPath())
		} else {
			err = store.WriteFileAtomic(vaultPath(), before, 0o600)
		}
		if nf.Mode == "keyfile" {
			_ = os.Remove(kp) // the old vault has a passphrase, so it never used it
		}
		return err
	}
	if err := nf.save(); err != nil {
		_ = putBack()
		return err
	}
	if err := readsBack(nf, newKey, plain); err != nil {
		if perr := putBack(); perr != nil {
			return fmt.Errorf("the new vault did not read back (%v), and the old one could not be put back: %v", err, perr)
		}
		return fmt.Errorf("the new vault did not read back (%v): the old one was put back, nothing changed", err)
	}
	return nil
}

// removeOldKey removes the key a vault of mode from had, now that nothing
// uses it: what it removed, or what is left and why.
func removeOldKey(from string) (removed, left string) {
	switch from {
	case "keyfile":
		kp := store.Path("vault.key")
		b, err := os.ReadFile(kp)
		if err != nil {
			return "", ""
		}
		_ = os.WriteFile(kp, make([]byte, len(b)), 0o600) // overwrite, then remove
		if err := os.Remove(kp); err != nil {
			return "", fmt.Sprintf("%s is still there (%v); nothing uses it now, remove it", kp, err)
		}
		return "vault.key", ""
	case "keychain":
		if err := keychainDel(); err != nil {
			return "", fmt.Sprintf("the old key is still in the keychain (%v); nothing uses it now, remove it there", err)
		}
		return "keychain", ""
	}
	return "", ""
}

// readsBack loads the vault from disk and checks that it is the one just
// written and that the new key (read back from vault.key for a key-file
// vault) opens every secret to the same value.
func readsBack(want *file, key []byte, plain map[string][]byte) error {
	g, err := load()
	if err != nil {
		return err
	}
	if g.Mode != want.Mode || !bytes.Equal(g.Salt, want.Salt) || len(g.Entries) != len(plain) {
		return errors.New("vault.json is not the one just written")
	}
	if g.Mode == "keyfile" {
		disk, err := os.ReadFile(store.Path("vault.key"))
		if err != nil {
			return err
		}
		if !bytes.Equal(disk, key) {
			return errors.New("vault.key is not the key just written")
		}
	}
	a, err := g.aeadFor(key)
	if err != nil {
		return err
	}
	got, err := g.openAll(a)
	if err != nil {
		return err
	}
	defer wipe(got)
	for name, pt := range plain {
		if !bytes.Equal(got[name], pt) {
			return fmt.Errorf("secret %q reads back different", name)
		}
	}
	return nil
}

// LeftoverKeyFile is the path of a vault.key the vault does not use (its
// key is a passphrase or in the keychain), or "". It still opens old copies
// of vault.json, in a backup say. A key change that could not remove the
// old key leaves one behind.
func LeftoverKeyFile() string {
	if _, err := os.Stat(vaultPath()); err != nil {
		return ""
	}
	f, err := load()
	if err != nil || f.Mode == "keyfile" {
		return ""
	}
	kp := store.Path("vault.key")
	if _, err := os.Stat(kp); err != nil {
		return ""
	}
	return kp
}
