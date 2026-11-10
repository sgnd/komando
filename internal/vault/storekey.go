package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/scrypt"

	"github.com/sgnd/komando/internal/store"
)

// The master key of the sealed store (docs/design/phase0-s6.md), kept the
// three ways the vault key is kept: in the OS keychain, in a key file
// beside the store (store.key, never vault.key), or made from the
// passphrase in $KOMANDO_VAULT_PASS with a salt kept in the store.
// sealrow derives the row key from it under its own label, so it is never
// used as is.

func init() { store.KeySource = storeMaster }

// storeKeyFile is the key file of a sealed store without a keychain.
func storeKeyFile() string { return store.Path("store.key") }

func storeMaster(meta map[string]string, create bool) ([]byte, map[string]string, error) {
	if create {
		return newStoreMaster()
	}
	switch meta["key_mode"] {
	case "passphrase":
		p := Passphrase()
		if p == "" {
			return nil, nil, ErrLocked
		}
		salt, err := hex.DecodeString(meta["salt"])
		n, nerr := strconv.Atoi(meta["scrypt_n"])
		if err != nil || len(salt) < 16 || nerr != nil || n < 2 {
			return nil, nil, fmt.Errorf("%w: the store's passphrase settings are damaged", ErrKey)
		}
		k, err := scrypt.Key([]byte(p), salt, n, 8, 1, keyLen)
		return k, nil, err
	case "keychain":
		k, err := keychainGet()
		if err != nil {
			return nil, nil, err
		}
		if len(k) < keyLen {
			return nil, nil, fmt.Errorf("%w: the keychain item holds %d bytes, not %d", ErrKey, len(k), keyLen)
		}
		return k[:keyLen], nil, nil
	case "keyfile":
		kp := storeKeyFile()
		b, err := os.ReadFile(kp)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %s is missing, and the store cannot be opened without it; restore it from a backup", ErrKey, kp)
		}
		if err != nil {
			return nil, nil, err
		}
		if len(b) < keyLen {
			return nil, nil, fmt.Errorf("%w: %s holds %d bytes, not %d (cut short?); restore it from a backup", ErrKey, kp, len(b), keyLen)
		}
		return b[:keyLen], nil, nil
	}
	return nil, nil, fmt.Errorf("%w: the store names an unknown key mode %q; update komando", ErrKey, meta["key_mode"])
}

// newStoreMaster picks where a new store's key lives, as a new vault does:
// the passphrase when one is given, else the keychain, else a key file.
func newStoreMaster() ([]byte, map[string]string, error) {
	if p := Passphrase(); p != "" {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
		k, err := scrypt.Key([]byte(p), salt, PassphraseN, 8, 1, keyLen)
		if err != nil {
			return nil, nil, err
		}
		return k, map[string]string{"key_mode": "passphrase", "salt": hex.EncodeToString(salt), "scrypt_n": strconv.Itoa(PassphraseN)}, nil
	}
	if k, ok := keychainNewKey(); ok && len(k) >= keyLen {
		return k[:keyLen], map[string]string{"key_mode": "keychain"}, nil
	}
	if err := store.EnsureHome(); err != nil {
		return nil, nil, err
	}
	k, err := newKeyFile(storeKeyFile())
	if err != nil {
		return nil, nil, err
	}
	if len(k) < keyLen {
		return nil, nil, fmt.Errorf("%w: %s holds %d bytes, not %d", ErrKey, storeKeyFile(), len(k), keyLen)
	}
	return k[:keyLen], map[string]string{"key_mode": "keyfile"}, nil
}
