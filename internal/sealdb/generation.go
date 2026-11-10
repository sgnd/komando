package sealdb

import (
	"context"
	"errors"
	"strconv"
)

// generationID is the record that counts the store's changes. Sealed like
// any record, so it cannot be set back without the key; a whole old copy
// of the file carries its old number, which the keychain catches.
const generationID, generationType = "generation", "generation"

func (t *Tx) generation() (uint64, error) {
	r, err := t.Get(generationID)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(r.Data), 10, 64)
}

func (t *Tx) bumpGeneration() (uint64, error) {
	n, err := t.generation()
	if err != nil {
		return 0, err
	}
	n++
	if _, err := t.write1(generationID, generationType, n, false, []byte(strconv.FormatUint(n, 10))); err != nil {
		return 0, err
	}
	return n, nil
}

// Generation is how many write steps changed this store's records (audit
// entries and readable settings do not count).
func (d *DB) Generation(ctx context.Context) (uint64, error) {
	var n uint64
	err := d.View(ctx, func(tx *Tx) error {
		var err error
		n, err = tx.generation()
		return err
	})
	return n, err
}
