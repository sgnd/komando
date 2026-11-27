package vault

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/store"
)

// On a sealed home each secret value lives in the store's credential
// record of the same name (store format 3: Credential.Value), and the
// approval code's seed in its own record, never a credential. Inside the
// record the value is still sealed by the vault, bound to its name, with
// the value key (sealkey.Values) made from the store's master key, so the
// store's row key never opens a value by itself.

// valueRow is one value the vault keeps, and the record that holds it.
type valueRow struct {
	id, typ, name string
	cred          *store.Credential // nil for the approval seed
}

type seedRecord struct {
	Value store.SealedValue `json:"value"`
}

// valueRows lists the records of tx that hold a value.
func valueRows(tx *sealdb.Tx) ([]valueRow, map[string]*entry, error) {
	var rows []valueRow
	entries := map[string]*entry{}
	add := func(r valueRow, v store.SealedValue, at time.Time) error {
		if r.name == "" || entries[r.name] != nil {
			return sealdb.ErrTampered
		}
		rows = append(rows, r)
		entries[r.name] = &entry{Nonce: v.Nonce, Data: v.Data, UpdatedAt: at, id: r.id}
		return nil
	}
	creds, err := tx.List(store.KindCredential)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range creds {
		var c store.Credential
		if err := json.Unmarshal(r.Data, &c); err != nil {
			return nil, nil, err
		}
		if c.Value == nil {
			continue
		}
		if err := add(valueRow{id: r.ID, typ: store.KindCredential, name: c.Name, cred: &c}, *c.Value, c.UpdatedAt); err != nil {
			return nil, nil, err
		}
	}
	seeds, err := tx.List(store.KindApprovalSeed)
	if err != nil {
		return nil, nil, err
	}
	if len(seeds) > 1 {
		return nil, nil, sealdb.ErrTampered
	}
	for _, r := range seeds {
		var sr seedRecord
		if err := json.Unmarshal(r.Data, &sr); err != nil {
			return nil, nil, err
		}
		if err := add(valueRow{id: r.ID, typ: store.KindApprovalSeed, name: store.ApprovalSeedName}, sr.Value, r.MTime); err != nil {
			return nil, nil, err
		}
	}
	return rows, entries, nil
}

// loadSealedTx reads the values of tx into a file.
func loadSealedTx(tx *sealdb.Tx) (*file, error) {
	_, entries, err := valueRows(tx)
	if err != nil {
		return nil, err
	}
	return &file{Entries: entries}, nil
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

// putValue writes e as name's value: into its credential record (which
// keeps every other field), a new token credential, or the seed record.
func putValue(tx *sealdb.Tx, name string, e *entry, row *valueRow) error {
	v := store.SealedValue{Nonce: e.Nonce, Data: e.Data}
	if name == store.ApprovalSeedName {
		b, err := json.Marshal(seedRecord{Value: v})
		if err != nil {
			return err
		}
		id := ""
		if row != nil {
			id = row.id
		}
		r, err := tx.Put(store.KindApprovalSeed, id, b)
		e.id = r.ID
		return err
	}
	c := &store.Credential{Name: name, Kind: store.CredToken}
	id := ""
	if row != nil && row.cred != nil {
		c, id = row.cred, row.id
	} else if r, ok, err := credByName(tx, name); err != nil {
		return err
	} else if ok {
		c, id = r.cred, r.id // a credential with no value yet (an outside item, a key) takes one
	}
	c.Name, c.Value, c.UpdatedAt = name, &v, e.UpdatedAt
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	r, err := tx.Put(store.KindCredential, id, b)
	e.id = r.ID
	return err
}

// credByName is the credential record named name, if any.
func credByName(tx *sealdb.Tx, name string) (valueRow, bool, error) {
	rows, err := tx.List(store.KindCredential)
	if err != nil {
		return valueRow{}, false, err
	}
	for _, r := range rows {
		var c store.Credential
		if err := json.Unmarshal(r.Data, &c); err != nil {
			return valueRow{}, false, err
		}
		if c.Name == name {
			return valueRow{id: r.ID, typ: store.KindCredential, name: name, cred: &c}, true, nil
		}
	}
	return valueRow{}, false, nil
}

// dropValue removes row's value: a credential that holds only its value
// goes; one that also names an outside item or a key keeps those.
func dropValue(tx *sealdb.Tx, row valueRow) error {
	if row.cred == nil || row.cred.Store == "" && row.cred.Key == nil && !row.cred.Ask {
		if err := tx.Delete(row.id); err != nil && !errors.Is(err, sealdb.ErrNotFound) {
			return err
		}
		return nil
	}
	c := *row.cred
	c.Value = nil
	b, err := json.Marshal(&c)
	if err != nil {
		return err
	}
	_, err = tx.Put(store.KindCredential, row.id, b)
	return err
}

// changeSealed is change on a sealed home: one write step of the store.
func changeSealed(fn func(f *file) error) error {
	d, err := store.DB(true)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		rows, entries, err := valueRows(tx)
		if err != nil {
			return err
		}
		f := &file{Entries: entries}
		byID := map[string]valueRow{}
		before := map[string]entry{}
		for _, r := range rows {
			byID[r.id] = r
			before[r.id] = *entries[r.name]
		}
		if err := fn(f); err != nil {
			return err
		}
		kept := map[string]bool{}
		for _, name := range sortedNames(f.Entries) {
			e := f.Entries[name]
			old, had := before[e.id]
			row, ok := byID[e.id]
			if had && ok && row.name == name && !kept[e.id] && string(old.Nonce) == string(e.Nonce) && string(old.Data) == string(e.Data) && old.UpdatedAt.Equal(e.UpdatedAt) {
				kept[e.id] = true
				continue
			}
			var at *valueRow
			if ok && row.name == name && !kept[e.id] {
				at = &row
			}
			if err := putValue(tx, name, e, at); err != nil {
				return err
			}
			kept[e.id] = true
		}
		for _, r := range rows {
			if !kept[r.id] {
				if err := dropValue(tx, r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// TicketMAC is the HMAC-SHA256 of msg under the ticket key, made from the
// store's master key (sealkey.Tickets): what komando's background
// commands check their parent's ticket with, so only a process that holds
// the master key makes one; the row key does not.
func TicketMAC(msg []byte) ([]byte, error) {
	m, err := store.MasterKey()
	if err != nil {
		return nil, err
	}
	defer clear(m)
	k, err := sealkey.Derive(m, sealkey.Tickets)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	h := hmac.New(sha256.New, k)
	h.Write(msg)
	return h.Sum(nil), nil
}

// sealedAEAD is the vault's key on a sealed home: the value key, made from
// the store's master key with no scrypt (the master key is random, or
// already scrypt of the passphrase).
func sealedAEAD() (cipher.AEAD, error) {
	m, err := store.MasterKey()
	if err != nil {
		return nil, err
	}
	defer clear(m)
	return vaultAEADFrom(m)
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

func sortedNames(m map[string]*entry) []string { return slices.Sorted(maps.Keys(m)) }
