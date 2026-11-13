package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// Moving a folder of before into the sealed store (komando seal).

// Secret is one secret with its value, for the move.
type Secret struct {
	Value     []byte
	UpdatedAt time.Time
}

// loadOld reads vault.json of a folder of before, only reading: a folder
// without one has no secrets.
func loadOld() (*file, error) {
	f := &file{Version: 1, Entries: map[string]*entry{}}
	b, err := os.ReadFile(store.Path("vault.json"))
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, fmt.Errorf("%s: %w", store.Path("vault.json"), err)
	}
	if f.Mode == modeSealed {
		return nil, errors.New("vault.json names the sealed store as its key")
	}
	if f.Entries == nil {
		f.Entries = map[string]*entry{}
	}
	return f, nil
}

// OldNames gives the secret names of a folder of before, without its key
// (a dry run of the move).
func OldNames() ([]string, error) {
	f, err := loadOld()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(f.Entries))
	for n := range f.Entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// ExportFiles reads every secret of a folder of before (vault.json), for
// the move. The caller wipes the values.
func ExportFiles() (map[string]Secret, error) {
	f, err := loadOld()
	if err != nil {
		return nil, err
	}
	out := map[string]Secret{}
	if len(f.Entries) == 0 {
		return out, nil
	}
	secret, err := f.key()
	if err != nil {
		return nil, err
	}
	a, err := f.aeadFor(secret)
	if err != nil {
		return nil, err
	}
	plain, err := f.openAll(a)
	if err != nil {
		return nil, err
	}
	for n, v := range plain {
		out[n] = Secret{Value: v, UpdatedAt: f.Entries[n].UpdatedAt}
	}
	return out, nil
}

// ImportSealed puts secrets into a sealed home's store in one write step,
// keeping when each was last changed.
func ImportSealed(secrets map[string]Secret) error {
	return changeSealed(func(f *file) error {
		a, err := f.aead()
		if err != nil {
			return err
		}
		for name, s := range secrets {
			nonce := make([]byte, a.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			f.Entries[name] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, s.Value, []byte(name)), UpdatedAt: s.UpdatedAt}
		}
		return nil
	})
}

// WipeSecrets clears the values.
func WipeSecrets(m map[string]Secret) {
	for _, s := range m {
		clear(s.Value)
	}
}

// KeychainKeyOfOldVault gives the key of a vault of before kept in the
// keychain, so the move's archive can bring vault.json back even after
// the keychain item changes. ok is false for other vaults.
func KeychainKeyOfOldVault() (key []byte, ok bool, err error) {
	f, err := loadOld()
	if err != nil || f.Mode != "keychain" {
		return nil, false, err
	}
	k, err := keychainGet()
	return k, err == nil, err
}

// RestoreKeychainKey puts a vault key of before back in the keychain for
// an undo: nothing when it is there already, an error when another key is.
func RestoreKeychainKey(key []byte) error {
	if have, err := keychainGet(); err == nil && bytes.Equal(have, key) {
		return nil
	}
	return keychainAdopt(key)
}
