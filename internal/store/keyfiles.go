package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The private key files of SSH keys. A key komando made (key gen,
// Managed) is kept by komando under keys/; the sealed local store of
// docs/design/sync-security.md section 16 takes over those behind these
// functions. A key added from elsewhere (key add) stays the person's own
// file at its path.

// ManagedKeyPath is where a key komando makes under name is kept.
func ManagedKeyPath(name string) string { return Path("keys", name) }

// ReadPrivateKey returns the private key file of k.
func ReadPrivateKey(k *Key) ([]byte, error) {
	return os.ReadFile(expandHome(k.Path))
}

// WriteManagedKey keeps the private and public parts of a key komando made
// under name, replacing what was there, and returns where the private part
// is. The private part is readable by this user only.
func WriteManagedKey(name string, private, public []byte) (string, error) {
	if err := ensureHome(); err != nil {
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
