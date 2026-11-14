package vault

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// Keychain is a store of secret items that the app komando runs inside
// supplies (the iPhone app's Keychain Services). When one is set, it
// replaces the operating system's tool for the store's key and its change
// count: the same items, under the same service and account names.
type Keychain interface {
	// Get is the item's value; nil and no error when there is none. An
	// error says nothing about whether the item is there (a phone before
	// its first unlock after a restart).
	Get(service, account string) ([]byte, error)
	// Put adds the item, or replaces its value.
	Put(service, account string, value []byte) error
	// Delete removes the item; no error when there is none.
	Delete(service, account string) error
}

type keychainBox struct{ k Keychain }

var hostKC atomic.Pointer[keychainBox]

// UseKeychain makes k the keychain of every call in this process. An app
// calls it once, before its first call; the komando program never does.
// With one set, KOMANDO_KEYCHAIN=off does not count, a store's key never
// goes to store.key, and an error of k is reported as such: komando never
// falls back to a key file.
func UseKeychain(k Keychain) {
	if k == nil {
		hostKC.Store(nil)
		return
	}
	hostKC.Store(&keychainBox{k})
}

// hostKeychain is the keychain UseKeychain set, or nil.
func hostKeychain() Keychain {
	if b := hostKC.Load(); b != nil {
		return b.k
	}
	return nil
}

// hostOS is what keychainOS reads as when the app supplies the keychain.
const hostOS = "host"

// kcOS is the keychain this process uses: "host" for the app's own
// (UseKeychain), else the operating system's (keychainOS).
func kcOS() string {
	if hostKeychain() != nil {
		return hostOS
	}
	return keychainOS
}

// KeychainError is a keychain the app supplies that could not be read or
// written. Its words are the app's own: it knows why (a phone before its
// first unlock after a restart) and what helps. The CLI shows it as
// KEYCHAIN_FAILED.
type KeychainError struct {
	Message, Hint string
}

func (e *KeychainError) Error() string { return e.Message }

// hostErr is err of the app's keychain, as a *KeychainError: the app's own
// one as it is, any other with plain words.
func hostErr(what string, err error) error {
	var ke *KeychainError
	if errors.As(err, &ke) {
		return ke
	}
	return &KeychainError{
		Message: fmt.Sprintf("the app's keychain could not %s (%v)", what, err),
		Hint:    "run it again; if it keeps failing, restart the app",
	}
}

// hostGet reads an item of the app's keychain: errNoKeychainKey when it
// holds none.
func hostGet(service string) ([]byte, error) {
	b, err := hostKeychain().Get(service, keychainAccount)
	if err != nil {
		return nil, hostErr("read the store's key", err)
	}
	if b == nil {
		return nil, errNoKeychainKey
	}
	return b, nil
}

// hostPut writes an item of the app's keychain.
func hostPut(service string, v []byte) error {
	if err := hostKeychain().Put(service, keychainAccount, v); err != nil {
		return hostErr("keep the store's key", err)
	}
	return nil
}

// hostDelete removes an item of the app's keychain.
func hostDelete(service string) error {
	if err := hostKeychain().Delete(service, keychainAccount); err != nil {
		return hostErr("remove an item", err)
	}
	return nil
}
