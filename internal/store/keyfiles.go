package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/sealdb"
)

// The private key files of SSH keys. A key komando made (key gen,
// Managed) is kept by komando under keys/; the sealed local store of
// docs/design/sync-security.md section 16 takes over those behind these
// functions. A key added from elsewhere (key add) stays the person's own
// file at its path.

// ManagedKeyPath is where a key komando makes under name is kept.
func ManagedKeyPath(name string) string { return Path("keys", name) }

// sealedKeyPrefix starts the Path of a key kept in the sealed store.
const sealedKeyPrefix = "sealed:"

// keyDataType is the store record of a key komando made: its private and
// public parts.
const keyDataType = "keydata"

type keyData struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// SealedKey reports a key kept inside the sealed store, which has no file.
func SealedKey(k *Key) bool { return strings.HasPrefix(k.Path, sealedKeyPrefix) }

// ReadPrivateKey returns the private key of k.
func ReadPrivateKey(k *Key) ([]byte, error) {
	if id, ok := strings.CutPrefix(k.Path, sealedKeyPrefix); ok {
		d, err := DB(false)
		if err != nil {
			return nil, err
		}
		var kd keyData
		err = d.View(context.Background(), func(tx *sealdb.Tx) error {
			r, err := tx.Get(id)
			if err != nil {
				return err
			}
			if r.Deleted || r.Type != keyDataType {
				return fmt.Errorf("key %s: %w", k.Name, sealdb.ErrNotFound)
			}
			return json.Unmarshal(r.Data, &kd)
		})
		return kd.Private, err
	}
	return os.ReadFile(expandHome(k.Path))
}

// WriteManagedKey keeps the private and public parts of a key komando made
// under name, replacing what was there, and returns where the private part
// is. The private part is readable by this user only.
func WriteManagedKey(name string, private, public []byte) (string, error) {
	if err := ensureHome(); err != nil {
		return "", err
	}
	if Sealed() {
		d, err := DB(true)
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(keyData{Private: private, Public: public})
		if err != nil {
			return "", err
		}
		var id string
		err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
			r, err := tx.Put(keyDataType, "", b)
			id = r.ID
			return err
		})
		return sealedKeyPrefix + id, err
	}
	if err := os.MkdirAll(Path("keys"), 0o700); err != nil {
		return "", err
	}
	p := ManagedKeyPath(name)
	if err := WriteFileAtomic(p, private, 0o600); err != nil {
		return "", err
	}
	if err := WriteFileAtomic(p+".pub", public, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// RemoveManagedKey deletes the files of a key komando made. A file that is
// gone already is not an error.
func RemoveManagedKey(k *Key) error {
	if !k.Managed {
		return errors.New("store: " + k.Path + " is not a key komando made")
	}
	if id, ok := strings.CutPrefix(k.Path, sealedKeyPrefix); ok {
		d, err := DB(false)
		if errors.Is(err, ErrNoStore) {
			return nil
		}
		if err != nil {
			return err
		}
		return d.Update(context.Background(), func(tx *sealdb.Tx) error {
			if err := tx.Delete(id); err != nil && !errors.Is(err, sealdb.ErrNotFound) {
				return err
			}
			return nil
		})
	}
	if err := os.Remove(k.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = os.Remove(k.Path + ".pub")
	return nil
}

func expandHome(p string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	return p
}
