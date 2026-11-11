package sealdb

import "context"

// generationID is the record that counts the store's changes. Sealed like
// any record, so it cannot be set back without the key; a whole old copy
// of the file carries its old number, which the keychain catches.
const generationID, generationType = "generation", "generation"

func (t *Tx) generation() (uint64, error) {
	s, err := t.index()
	if err != nil {
		return 0, err
	}
	return s.gen, nil
}

// Generation is how many write steps changed this store's records or added
// audit entries (readable settings do not count).
func (d *DB) Generation(ctx context.Context) (uint64, error) {
	var n uint64
	err := d.View(ctx, func(tx *Tx) error {
		var err error
		n, err = tx.generation()
		return err
	})
	return n, err
}
