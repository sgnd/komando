package sealdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/sealrow"
)

// The meta table is readable without the key (Peek): komando needs its
// key mode, salt and scrypt cost before it can open anything. So that it
// cannot be changed unseen, a sealed record holds a copy of it: every
// write of meta writes the copy in the same step, and an open compares
// them. A store made before the copy existed has none until a person
// carries it over (SealMeta); until then it opens as before.

const metaSealID, metaSealType = "metaseal", "metaseal"

// SealNewStores: Create seals a new store's meta table. Tests set it
// false to make a store as an older komando did; nothing else changes it.
var SealNewStores = true

// ErrMetaTampered: the meta table does not match its sealed copy.
var ErrMetaTampered = fmt.Errorf("the store's settings row does not match its sealed copy: %w", ErrTampered)

// metaText is the meta table, sorted, one k=v line each.
func (t *Tx) metaText() ([]byte, error) {
	rows, err := t.c.QueryContext(t.ctx, `SELECT k,v FROM meta ORDER BY k`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var b bytes.Buffer
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.Bytes(), rows.Err()
}

// metaSealState says whether the sealed copy exists and matches.
func (t *Tx) metaSealState() (have, match bool, err error) {
	r, err := t.Get(metaSealID)
	if errors.Is(err, ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if r.Type != metaSealType || r.Deleted {
		return true, false, nil
	}
	now, err := t.metaText()
	if err != nil {
		return true, false, err
	}
	return true, bytes.Equal(now, r.Data), nil
}

// SealMeta writes the sealed copy of the meta table as it is now: on a
// new store, after every meta write, and when a person carries an older
// store over (or reseals it after checking it, doctor --reseal-meta).
func (t *Tx) SealMeta() error {
	if !t.write {
		return ErrReadOnly
	}
	b, err := t.metaText()
	if err != nil {
		return err
	}
	_, err = t.Put(metaSealType, metaSealID, b)
	return err
}

// MetaSealed reports whether the store has the sealed copy of its meta
// table (an older store has none until a person carries it over).
func (d *DB) MetaSealed(ctx context.Context) (bool, error) {
	var have bool
	err := d.View(ctx, func(tx *Tx) error {
		var err error
		have, _, err = tx.metaSealState()
		return err
	})
	return have, err
}

// ResealMeta is the way back from ErrMetaTampered, for a person: it opens
// the store at path with key without comparing the meta table, checks
// that key opens every record and audit entry (so the key, and the meta
// it was made from, are the right ones), and seals the meta table as it
// is now. It returns the meta it sealed. A record that does not open
// stops it and changes nothing.
func ResealMeta(ctx context.Context, path string, key *sealrow.Key) (map[string]string, error) {
	d, err := openFile(ctx, path, key, false, true)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	meta := map[string]string{}
	err = d.Update(ctx, func(tx *Tx) error {
		ids, err := tx.recordIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Get(id); err != nil && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("record %s: %w", id, err)
			}
		}
		if _, err := tx.Audit(0, 1<<30); err != nil {
			return err
		}
		if err := tx.SealMeta(); err != nil {
			return err
		}
		rows, err := tx.c.QueryContext(tx.ctx, `SELECT k,v FROM meta`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			meta[k] = v
		}
		return rows.Err()
	})
	return meta, err
}

// recordIDs are the IDs of every record row.
func (t *Tx) recordIDs() ([]string, error) {
	rows, err := t.c.QueryContext(t.ctx, `SELECT id FROM records`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
