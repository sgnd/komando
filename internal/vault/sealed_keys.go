package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
	"github.com/sgnd/komando/internal/store"
)

// Moving and changing the key of a sealed store.
// Moving it between the keychain and store.key moves the same key; a new
// passphrase, or leaving one, makes a new master key and seals the whole
// store again in one write step. A new key is kept before the store uses
// it, and the old one goes only after.

func storeMeta() (map[string]string, error) {
	m, err := sealdb.Peek(context.Background(), store.DBPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNoStore
	}
	return m, err
}

func vaultAEADFrom(master []byte) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, master, nil, vaultHKDFLabel, 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// passMaster is the master key of a passphrase store for pass.
func passMaster(meta map[string]string, pass string) ([]byte, error) {
	salt, err := hex.DecodeString(meta["salt"])
	n, nerr := strconv.Atoi(meta["scrypt_n"])
	if err != nil || nerr != nil || len(salt) < 16 || n < 2 {
		return nil, fmt.Errorf("%w: the store's passphrase settings are damaged", ErrKey)
	}
	return scrypt.Key([]byte(pass), salt, n, 8, 1, keyLen)
}

// opensStore reports ErrWrongKey when master does not open the store.
func opensStore(master []byte) error {
	k, err := sealrow.NewKey(master)
	if err != nil {
		return err
	}
	d, err := sealdb.Open(context.Background(), store.DBPath(), k)
	if errors.Is(err, sealdb.ErrWrongKey) {
		return ErrWrongKey
	}
	if err != nil {
		return err
	}
	return d.Close()
}

// sealedOpens is Opens on a sealed home.
func sealedOpens(oldPass string) error {
	meta, err := storeMeta()
	if errors.Is(err, store.ErrNoStore) {
		return nil
	}
	if err != nil {
		return err
	}
	var m []byte
	if oldPass != "" && meta["key_mode"] == "passphrase" {
		m, err = passMaster(meta, oldPass)
	} else {
		m, _, err = storeMaster(meta, false)
	}
	if err != nil {
		return err
	}
	defer clear(m)
	return opensStore(m)
}

// sealedChangeKey is ChangeKey on a sealed home.
func sealedChangeKey(w store.Write, oldPass, newPass string) (KeyChange, error) {
	var res KeyChange
	if newPass != "" && utf8.RuneCountInString(newPass) < MinPassphrase {
		return res, ErrShortPassphrase
	}
	if w == store.Preview {
		return res, store.ErrDryRun
	}
	meta, err := storeMeta()
	if errors.Is(err, store.ErrNoStore) {
		if newPass == "" {
			return res, ErrNoPassphrase
		}
		// no store yet: the first one is made with this passphrase
		passMu.Lock()
		pass = newPass
		passMu.Unlock()
		if _, err := store.DB(true); err != nil {
			return res, err
		}
		res.To = "passphrase"
		return res, nil
	}
	if err != nil {
		return res, err
	}
	res.From = meta["key_mode"]
	if newPass == "" && res.From != "passphrase" {
		return res, ErrNoPassphrase
	}
	var oldMaster []byte
	if oldPass != "" && res.From == "passphrase" {
		oldMaster, err = passMaster(meta, oldPass)
	} else {
		oldMaster, _, err = storeMaster(meta, false)
	}
	if err != nil {
		return res, err
	}
	defer clear(oldMaster)
	if err := opensStore(oldMaster); err != nil {
		return res, err
	}
	if oldPass != "" {
		passMu.Lock()
		pass = oldPass // so the store opens with it below
		passMu.Unlock()
	}
	newMaster, newMeta, err := newStoreKey(newPass)
	if err != nil {
		return res, err
	}
	defer clear(newMaster)
	if newPass == "" {
		// the key first: a store sealed with a key nobody kept is lost
		if err := writeNewKeyFile(newMaster); err != nil {
			return res, err
		}
	}
	oldA, err := vaultAEADFrom(oldMaster)
	if err != nil {
		return res, err
	}
	newA, err := vaultAEADFrom(newMaster)
	if err != nil {
		return res, err
	}
	err = store.Rekey(newMaster, newMeta, func(tx *sealdb.Tx) error {
		n, err := resealSecrets(tx, oldA, newA)
		res.Secrets = n
		return err
	})
	if newPass == "" {
		// the new key takes its real name only once the store uses it
		if ferr := settleNewKeyFile(); err == nil {
			err = ferr
		}
	}
	if err != nil {
		return res, err
	}
	res.To = newMeta["key_mode"]
	passMu.Lock()
	pass = newPass // the rest of this command opens the store with it
	passMu.Unlock()
	res.Removed, res.Left = removeOldStoreKey(res.From)
	return res, nil
}

// removeOldStoreKey removes the key a store used before a change: its
// key file (overwritten first) or its keychain item.
func removeOldStoreKey(from string) (removed, left string) {
	switch from {
	case "keyfile":
		kp := storeKeyFile()
		if b, err := os.ReadFile(kp); err == nil {
			_ = os.WriteFile(kp, make([]byte, len(b)), 0o600)
			if err := os.Remove(kp); err != nil {
				return "", fmt.Sprintf("%s is still there (%v); nothing uses it now, remove it", kp, err)
			}
			return "store.key", ""
		}
	case "keychain":
		genDel()
		if err := keychainDel(); err != nil {
			return "", fmt.Sprintf("the old key is still in the keychain (%v); nothing uses it now, remove it there", err)
		}
		return "keychain", ""
	}
	return "", ""
}

// newStoreKey makes the master key for a passphrase, or a random one for
// a key file when pass is "".
func newStoreKey(pass string) ([]byte, map[string]string, error) {
	if pass == "" {
		k := make([]byte, keyLen)
		if _, err := rand.Read(k); err != nil {
			return nil, nil, err
		}
		return k, map[string]string{"key_mode": "keyfile", "salt": "", "scrypt_n": ""}, nil
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	k, err := scrypt.Key([]byte(pass), salt, PassphraseN, 8, 1, keyLen)
	return k, map[string]string{"key_mode": "passphrase", "salt": hex.EncodeToString(salt), "scrypt_n": strconv.Itoa(PassphraseN)}, err
}

// writeNewKeyFile writes store.key, which must not be there.
func writeNewKeyFile(key []byte) error {
	if _, err := os.Stat(storeKeyFile()); err == nil {
		return fmt.Errorf("%s is already there; nothing uses it, remove it first", storeKeyFile())
	}
	f, err := os.OpenFile(newKeyFilePath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func newKeyFilePath() string { return storeKeyFile() + ".new" }

// settleNewKeyFile is called after a change to a key file, whether it
// worked or not. When the store now names a key file, store.key.new is
// its key and becomes store.key; otherwise the change did not happen and
// store.key.new is removed.
func settleNewKeyFile() error {
	np := newKeyFilePath()
	if _, err := os.Stat(np); err != nil {
		return nil
	}
	meta, err := storeMeta()
	if err != nil {
		return err // keep the file: it may be the only key
	}
	if meta["key_mode"] == "keyfile" {
		return os.Rename(np, storeKeyFile())
	}
	return os.Remove(np)
}

// resealSecrets seals every secret's value again with newA, inside the
// rekey step.
func resealSecrets(tx *sealdb.Tx, oldA, newA cipher.AEAD) (int, error) {
	rows, err := tx.List(secretType)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		var e sealedEntry
		if err := json.Unmarshal(r.Data, &e); err != nil {
			return 0, err
		}
		pt, err := oldA.Open(nil, e.Nonce, e.Data, []byte(e.Name))
		if err != nil {
			return 0, fmt.Errorf("%w %q", ErrDecrypt, e.Name)
		}
		nonce := make([]byte, newA.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}
		e.Nonce, e.Data = nonce, newA.Seal(nil, nonce, pt, []byte(e.Name))
		clear(pt)
		b, err := json.Marshal(e)
		if err != nil {
			return 0, err
		}
		if _, err := tx.Put(secretType, r.ID, b); err != nil {
			return 0, err
		}
	}
	return len(rows), nil
}

// sealedKeyToKeychain is KeyToKeychain on a sealed home: the key in
// store.key moves into the keychain.
func sealedKeyToKeychain() (string, error) {
	tool, err := autoKeychainTool() // a clear error, never macOS's dialog
	if err != nil {
		return "", err
	}
	meta, err := storeMeta()
	if errors.Is(err, store.ErrNoStore) {
		if _, err := store.DB(true); err != nil { // a new store picks the keychain itself
			return "", err
		}
		if meta, err = storeMeta(); err == nil && meta["key_mode"] == "keychain" {
			return tool, nil
		}
	}
	if err != nil {
		return "", err
	}
	switch meta["key_mode"] {
	case "keychain":
		return tool, nil
	case "passphrase":
		return "", errors.New("this store is unlocked with KOMANDO_VAULT_PASS, not a key file: nothing to move")
	}
	kp := storeKeyFile()
	key, err := os.ReadFile(kp)
	if err != nil {
		return "", err
	}
	if err := keychainAdopt(key); err != nil {
		return "", err
	}
	// the change count first: a keychain store without one never opens
	if err := store.StartGeneration(); err != nil {
		return "", err
	}
	if err := store.SetStoreMeta(map[string]string{"key_mode": "keychain"}); err != nil {
		genDel()
		return "", err
	}
	// overwrite, then remove: the key now lives only in the keychain
	_ = os.WriteFile(kp, make([]byte, len(key)), 0o600)
	return tool, os.Remove(kp)
}

// sealedKeyToFile is KeyToFile on a sealed home.
func sealedKeyToFile() error {
	meta, err := storeMeta()
	if errors.Is(err, store.ErrNoStore) {
		return nil
	}
	if err != nil {
		return err
	}
	if meta["key_mode"] != "keychain" {
		return nil
	}
	key, err := keychainGet()
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(storeKeyFile(), key, 0o600); err != nil {
		return err
	}
	if err := store.SetStoreMeta(map[string]string{"key_mode": "keyfile"}); err != nil {
		return err
	}
	genDel()
	return keychainDel()
}
