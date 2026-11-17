package vault

import (
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/store"
)

// Changing the store's key (`komando secret passphrase`, sealed_keys.go).

// ErrWrongKey: a key that does not open the vault (a wrong
// KOMANDO_VAULT_PASS, say).
var ErrWrongKey = errors.New("the key does not open the vault")

// ErrShortPassphrase: a new passphrase must have MinPassphrase characters.
var ErrShortPassphrase = fmt.Errorf("a vault passphrase needs %d or more characters", MinPassphrase)

// ErrNoPassphrase: the vault has no passphrase to take away.
var ErrNoPassphrase = errors.New("the vault has no passphrase")

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
// otherwise "". A preview (a dry run) stops with store.ErrDryRun.
func ChangeKey(w store.Write, oldPass, newPass string) (KeyChange, error) {
	return sealedChangeKey(w, oldPass, newPass)
}
