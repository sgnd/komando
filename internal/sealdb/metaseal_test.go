package sealdb

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// rawMeta changes the meta table behind komando's back, as someone with
// the file could.
func rawMeta(t *testing.T, path, sqlText string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(sqlText, args...); err != nil {
		t.Fatal(err)
	}
}

// A new store seals its meta table; a meta write keeps the copy; a change
// from outside stops the next open (C08).
func TestMetaSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	if have, err := d.MetaSealed(ctx); err != nil || !have {
		t.Fatalf("a new store: %v %v", have, err)
	}
	if err := d.Update(ctx, func(tx *Tx) error { return tx.SetMeta("scrypt_n", "131072") }); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2, err := Open(ctx, path, key(t, 1))
	if err != nil {
		t.Fatalf("after a meta write: %v", err)
	}
	d2.Close()
	rawMeta(t, path, `UPDATE meta SET v='1024' WHERE k='scrypt_n'`)
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrMetaTampered) || !errors.Is(err, ErrTampered) {
		t.Fatalf("a faked scrypt_n opened: %v", err)
	}
	rawMeta(t, path, `UPDATE meta SET v='131072' WHERE k='scrypt_n'`)
	rawMeta(t, path, `INSERT INTO meta(k,v) VALUES('key_mode','keychain')`)
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrMetaTampered) {
		t.Fatalf("an added row opened: %v", err)
	}
}

// A store from before the sealed copy opens as before, keeps opening
// after meta writes, and is sealed only by SealMeta (a person's carry-over).
func TestMetaSealCarryOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	SealNewStores = false // as an older komando made it
	d := open(t, path)
	SealNewStores = true
	d.Close()
	d, err := Open(ctx, path, key(t, 1))
	if err != nil {
		t.Fatalf("an older store: %v", err)
	}
	defer d.Close()
	if err := d.Update(ctx, func(tx *Tx) error { return tx.SetMeta("key_mode", "keyfile") }); err != nil {
		t.Fatal(err)
	}
	if have, _ := d.MetaSealed(ctx); have {
		t.Fatal("a meta write sealed an older store")
	}
	if err := d.Update(ctx, func(tx *Tx) error { return tx.SealMeta() }); err != nil {
		t.Fatal(err)
	}
	if have, _ := d.MetaSealed(ctx); !have {
		t.Fatal("not sealed after SealMeta")
	}
}

// ResealMeta opens a store whose meta was changed, with the right key,
// checks every record and seals the meta again; the wrong key changes
// nothing.
func TestResealMeta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	if err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err }); err != nil {
		t.Fatal(err)
	}
	d.Close()
	rawMeta(t, path, `INSERT INTO meta(k,v) VALUES('note','x')`)
	if _, err := ResealMeta(ctx, path, key(t, 2)); err == nil {
		t.Fatal("the wrong key resealed")
	}
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrMetaTampered) {
		t.Fatalf("the wrong key changed something: %v", err)
	}
	m, err := ResealMeta(ctx, path, key(t, 1))
	if err != nil || m["note"] != "x" {
		t.Fatalf("reseal: %v %v", m, err)
	}
	d2, err := Open(ctx, path, key(t, 1))
	if err != nil {
		t.Fatalf("after reseal: %v", err)
	}
	d2.Close()
}
