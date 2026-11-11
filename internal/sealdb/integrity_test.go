package sealdb

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
)

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	return raw
}

func put(t *testing.T, d *DB, typ, id, data string) string {
	t.Helper()
	var out string
	if err := d.Update(ctx, func(tx *Tx) error {
		r, err := tx.Put(typ, id, []byte(data))
		out = r.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// H1: a handle opened before another one changed the key stops before it
// writes anything with the old key, and the store stays readable.
func TestKeyChangedByAnotherHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	a := open(t, path)
	b := open(t, path)
	put(t, a, "server", "", "web")
	if err := a.Rekey(ctx, key(t, 2), nil); err != nil {
		t.Fatal(err)
	}
	err := b.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte("old key")) })
	if !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("write with the old key: %v", err)
	}
	if err := b.View(ctx, func(*Tx) error { return nil }); !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("read with the old key: %v", err)
	}
	c, err := Open(ctx, path, key(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte("new key")) }); err != nil {
		t.Fatal(err)
	}
	_ = c.View(ctx, func(tx *Tx) error {
		if a, err := tx.Audit(0, 100); err != nil || len(a) != 1 {
			t.Fatalf("audit: %v %v", a, err)
		}
		return nil
	})
	if err := c.Rekey(ctx, key(t, 3), nil); err != nil {
		t.Fatalf("a later rekey: %v", err)
	}
}

// H2: an old copy of one row written back is caught by Get and List.
func TestRowRolledBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	id := put(t, d, "server", "", "protected=false")
	raw := rawDB(t, path)
	var (
		ver  int64
		mt   int64
		data []byte
	)
	if err := raw.QueryRow(`SELECT version,mtime,data FROM records WHERE id=?`, id).Scan(&ver, &mt, &data); err != nil {
		t.Fatal(err)
	}
	put(t, d, "server", id, "protected=true")
	if _, err := raw.Exec(`UPDATE records SET version=?,mtime=?,data=? WHERE id=?`, ver, mt, data, id); err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		if _, err := tx.Get(id); !errors.Is(err, ErrTampered) {
			t.Fatalf("get: %v", err)
		}
		if _, err := tx.List("server"); !errors.Is(err, ErrTampered) {
			t.Fatalf("list: %v", err)
		}
		return nil
	})
	// nor can a write build on it
	_, err := func() (Record, error) {
		var r Record
		err := d.Update(ctx, func(tx *Tx) error { var err error; r, err = tx.Put("server", id, []byte("x")); return err })
		return r, err
	}()
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("put over it: %v", err)
	}
}

// H2: a row removed is caught by Get, List, Put and Delete.
func TestRowRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	put(t, d, "rule", "", "allow")
	id := put(t, d, "rule", "", "deny rm")
	if _, err := rawDB(t, path).Exec(`DELETE FROM records WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		if _, err := tx.Get(id); !errors.Is(err, ErrTampered) {
			t.Fatalf("get: %v", err)
		}
		if _, err := tx.List("rule"); !errors.Is(err, ErrTampered) {
			t.Fatalf("list: %v", err)
		}
		return nil
	})
	if err := d.Update(ctx, func(tx *Tx) error { return tx.Delete(id) }); !errors.Is(err, ErrTampered) {
		t.Fatalf("delete: %v", err)
	}
	if err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("rule", id, nil); return err }); !errors.Is(err, ErrTampered) {
		t.Fatalf("put: %v", err)
	}
}

// M2: entries cut from the end are caught, even with sqlite_sequence set
// back; the chain and head survive a rekey.
func TestAuditTailCut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	for i := range 5 {
		if err := d.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte(strconv.Itoa(i))) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Rekey(ctx, key(t, 2), nil); err != nil {
		t.Fatal(err)
	}
	read := func(after int64, limit int) ([]AuditRow, error) {
		var a []AuditRow
		err := d.View(ctx, func(tx *Tx) error { var err error; a, err = tx.Audit(after, limit); return err })
		return a, err
	}
	if a, err := read(0, 100); err != nil || len(a) != 5 || string(a[4].Data) != "4" {
		t.Fatalf("after rekey: %v %v", a, err)
	}
	if a, err := read(2, 2); err != nil || len(a) != 2 {
		t.Fatalf("a page: %v %v", a, err)
	}
	if a, err := read(5, 10); err != nil || len(a) != 0 {
		t.Fatalf("past the end: %v %v", a, err)
	}
	if _, err := rawDB(t, path).Exec(`DELETE FROM audit WHERE seq>3; UPDATE sqlite_sequence SET seq=3 WHERE name='audit'`); err != nil {
		t.Fatal(err)
	}
	if a, err := read(0, 100); !errors.Is(err, ErrTampered) || len(a) != 3 {
		t.Fatalf("cut tail: %d %v", len(a), err)
	}
	if _, err := read(3, 100); !errors.Is(err, ErrTampered) {
		t.Fatalf("cut tail from its end: %v", err)
	}
}

// An entry undone with its savepoint leaves the head as it was.
func TestAuditSavepointUndone(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	err := d.Update(ctx, func(tx *Tx) error {
		_ = tx.AppendAudit([]byte("kept"))
		_ = d.Update(ctx, func(in *Tx) error { _ = in.AppendAudit([]byte("undone")); return errors.New("no") })
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		if a, err := tx.Audit(0, 10); err != nil || len(a) != 1 {
			t.Fatalf("audit: %v %v", a, err)
		}
		return nil
	})
}

// A store from before the index (a generation of digits only) is read as
// it is and gets its index with the next change.
func TestIndexUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	id := put(t, d, "server", "", "web")
	_ = d.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte("a")) })
	var gen uint64
	_ = d.Update(ctx, func(tx *Tx) error {
		g, err := tx.generation()
		gen = g
		if err != nil {
			return err
		}
		_, err = tx.write1(generationID, generationType, g, false, []byte(strconv.FormatUint(g, 10)))
		return err
	})
	_ = d.View(ctx, func(tx *Tx) error {
		if s, err := tx.index(); err != nil || !s.upgrade || s.gen != gen {
			t.Fatalf("old store: %+v %v", s, err)
		}
		if _, err := tx.Get(id); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	_ = d.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte("b")) })
	_ = d.View(ctx, func(tx *Tx) error {
		s, err := tx.index()
		if err != nil || s.upgrade || s.m[id].ver != 1 || s.head.seq != 2 {
			t.Fatalf("upgraded: %+v %v", s, err)
		}
		if a, err := tx.Audit(0, 10); err != nil || len(a) != 2 {
			t.Fatalf("audit: %v %v", a, err)
		}
		return nil
	})
}
