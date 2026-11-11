package vault

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"sort"
)

// Changing the store's key (`komando secret passphrase`, sealed_keys.go),
// and opening every secret of a vault of before (openAll, for `komando
// seal`).

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

func wipe(plain map[string][]byte) {
	for _, pt := range plain {
		clear(pt)
	}
}

// Opens checks, without changing anything, that every secret decrypts with
// the vault's current key (see ChangeKey for oldPass). An error that
// matches ErrWrongKey means one did not.
func Opens(oldPass string) error { return sealedOpens(oldPass) }

// KeyChange is what ChangeKey did.
type KeyChange struct {
	From    string `json:"from"`              // keyfile | passphrase | keychain; "" when there was no vault
	To      string `json:"to"`                // passphrase | keyfile
	Secrets int    `json:"secrets"`           // how many were sealed again
	Removed string `json:"removed,omitempty"` // the old key that was removed: store.key | keychain
	Left    string `json:"left,omitempty"`    // the old key that could not be removed, and why
}

// ChangeKey seals every secret again under a new key: the passphrase
// newPass, or, when it is "", a new random key (sealed_keys.go). oldPass is
// the current passphrase when KOMANDO_VAULT_PASS does not hold it,
// otherwise "".
func ChangeKey(oldPass, newPass string) (KeyChange, error) {
	return sealedChangeKey(oldPass, newPass)
}
