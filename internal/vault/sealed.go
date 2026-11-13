package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

// On a sealed home each secret is a record of
// the store, of type "secret". Inside it the value is still sealed by the
// vault as before, bound to its name, with a key made from the store's
// master key under its own label, so the store's row key never opens a
// value by itself.

const (
	secretType     = "secret"
	vaultHKDFLabel = "komando vault entries v1"
)

type sealedEntry struct {
	Name      string    `json:"name"`
	Nonce     []byte    `json:"nonce"`
	Data      []byte    `json:"data"`
	UpdatedAt time.Time `json:"updated_at"`
}

// loadSealedTx reads the secrets of tx into a file.
func loadSealedTx(tx *sealdb.Tx) (*file, error) {
	f := &file{Entries: map[string]*entry{}}
	rows, err := tx.List(secretType)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		var e sealedEntry
		if err := json.Unmarshal(r.Data, &e); err != nil {
			return nil, err
		}
		if e.Name == "" || f.Entries[e.Name] != nil {
			return nil, sealdb.ErrTampered
		}
		f.Entries[e.Name] = &entry{Nonce: e.Nonce, Data: e.Data, UpdatedAt: e.UpdatedAt, id: r.ID}
	}
	return f, nil
}

func loadSealed() (*file, error) {
	d, err := store.DB(false)
	if errors.Is(err, store.ErrNoStore) {
		return &file{Entries: map[string]*entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f *file
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		var err error
		f, err = loadSealedTx(tx)
		return err
	})
	return f, err
}

// changeSealed is change on a sealed home: one write step of the store.
func changeSealed(fn func(f *file) error) error {
	d, err := store.DB(true)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		f, err := loadSealedTx(tx)
		if err != nil {
			return err
		}
		before := map[string]entry{}
		for _, e := range f.Entries {
			before[e.id] = *e
		}
		if err := fn(f); err != nil {
			return err
		}
		kept := map[string]bool{}
		for name, e := range f.Entries {
			old, had := before[e.id]
			if had && e.id != "" && !kept[e.id] && string(old.Nonce) == string(e.Nonce) && string(old.Data) == string(e.Data) && old.UpdatedAt.Equal(e.UpdatedAt) {
				kept[e.id] = true
				continue
			}
			id := e.id
			if kept[id] {
				id = "" // a copy that took another entry's ID
			}
			b, err := json.Marshal(sealedEntry{Name: name, Nonce: e.Nonce, Data: e.Data, UpdatedAt: e.UpdatedAt})
			if err != nil {
				return err
			}
			r, err := tx.Put(secretType, id, b)
			if err != nil {
				return err
			}
			e.id = r.ID
			kept[r.ID] = true
		}
		for id := range before {
			if !kept[id] {
				if err := tx.Delete(id); err != nil && !errors.Is(err, sealdb.ErrNotFound) {
					return err
				}
			}
		}
		return nil
	})
}

// sealedAEAD is the vault's key on a sealed home: HKDF of the store's
// master key, no scrypt (the master key is random, or already scrypt of
// the passphrase).
func sealedAEAD() (cipher.AEAD, error) {
	m, err := store.MasterKey()
	if err != nil {
		return nil, err
	}
	defer clear(m)
	k, err := hkdf.Key(sha256.New, m, nil, vaultHKDFLabel, 32)
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

// sealedStrength is Check on a sealed home: the store's key mode.
func sealedStrength() (Strength, error) {
	meta, err := sealdb.Peek(context.Background(), store.DBPath())
	if errors.Is(err, os.ErrNotExist) {
		return Strength{NoVaultYet: true}, nil
	}
	if err != nil {
		return Strength{}, err
	}
	s := Strength{Mode: meta["key_mode"]}
	if n, err := strconv.Atoi(meta["scrypt_n"]); err == nil {
		s.ScryptN = n
	}
	if s.Mode == "passphrase" {
		s.OldKDF = s.ScryptN < PassphraseN
		s.ShortPass = len([]rune(Passphrase())) < MinPassphrase
	}
	return s, nil
}
