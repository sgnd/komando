package sealdb

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// rawData is the sealed bytes of record id as they sit in the file.
func rawData(t *testing.T, d *DB, id string) []byte {
	t.Helper()
	var b []byte
	if err := d.View(context.Background(), func(tx *Tx) error {
		return tx.c.QueryRowContext(tx.ctx, `SELECT data FROM records WHERE id=?`, id).Scan(&b)
	}); err != nil {
		t.Fatal(err)
	}
	return b
}

// A deleted record, and a record sealed again under a new key, leave no
// copy of the old sealed bytes in the file: with the old key (a key file
// that leaked, the reason for a new one) they would still open.
func TestOldSealedBytesErased(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	big := bytes.Repeat([]byte("secret value "), 400)
	var gone, kept string
	if err := d.Update(ctx, func(tx *Tx) error {
		r, err := tx.Put("secret", "", big)
		gone = r.ID
		if err == nil {
			r, err = tx.Put("secret", "", big[:200])
			kept = r.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	oldGone, oldKept := rawData(t, d, gone), rawData(t, d, kept)
	if err := d.Update(ctx, func(tx *Tx) error { return tx.Delete(gone) }); err != nil {
		t.Fatal(err)
	}
	if err := d.Rekey(ctx, key(t, 2), nil); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// a 64-byte piece is enough to tell the old bytes are still there
	if bytes.Contains(b, oldGone[20:84]) {
		t.Error("a deleted record's sealed bytes are still in the file")
	}
	if bytes.Contains(b, oldKept[20:84]) {
		t.Error("a record's bytes sealed with the old key are still in the file")
	}
}
