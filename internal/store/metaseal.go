package store

import (
	"context"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/sealdb"
)

// The store's meta table (key mode, salt, scrypt cost) is readable
// without the key; a sealed copy of it lets komando notice a change made
// outside komando (sealdb.ErrMetaTampered). A store made before the copy
// existed has none: a person's command carries it over (SealMeta), never
// an AI agent's or a script's.

// MetaSealed reports whether this home's store has the sealed copy; a
// home without a store counts as sealed (a new store gets it).
func MetaSealed() (bool, error) {
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return d.MetaSealed(context.Background())
}

// SealMeta gives this home's store the sealed copy of its meta table when
// it has none and this process already opened it (a command that did not
// open the store opens nothing for it). It reports whether it wrote one.
func SealMeta() (bool, error) {
	dbMu.Lock()
	_, open := dbOpen[Home()]
	dbMu.Unlock()
	if !open {
		return false, nil
	}
	have, err := MetaSealed()
	if err != nil || have {
		return false, err
	}
	d, err := DB(false)
	if err != nil {
		return false, err
	}
	return true, d.Update(context.Background(), func(tx *sealdb.Tx) error { return tx.SealMeta() })
}

// ResealMeta is doctor --reseal-meta: this home's store is closed, opened
// with its key without comparing its meta table, every record checked,
// and its meta sealed again. It returns the meta it kept. An older copy
// than the keychain remembers is not resealed: the write would raise its
// change count, and it could pass for the newest.
func ResealMeta() (map[string]string, error) {
	path := DBPath()
	meta, err := sealdb.Peek(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if KeySource == nil {
		return nil, errors.New("store: no key source")
	}
	master, _, err := KeySource(meta, false)
	if err != nil {
		return nil, err
	}
	ks, err := keysFor(master, meta["format"])
	if err != nil {
		return nil, err
	}
	Close()
	return sealdb.ResealMeta(context.Background(), path, ks.row, func(d *sealdb.DB) error {
		// the safety rows must match their MAC; the new meta seal gets a
		// new one in the same step
		if ks.policy != nil {
			if err := d.SetPolicy(context.Background(), ks.policy); err != nil {
				return err
			}
		}
		// a store it does not find checked has its writes stopped
		_, raise, err := checkGeneration(d, meta, false)
		d.OnGeneration = committer(raise)
		d.OnWait = waitNotice(os.Stderr)
		return err
	})
}
