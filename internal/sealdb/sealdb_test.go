package sealdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/sealrow"
)

var ctx = context.Background()

func key(t testing.TB, fill byte) *sealrow.Key {
	t.Helper()
	k, err := sealrow.NewKey(bytes.Repeat([]byte{fill}, sealrow.MasterLen))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func open(t *testing.T, path string) *DB {
	t.Helper()
	d, err := Open(ctx, path, key(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestPutGetListDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	var id string
	err := d.Update(ctx, func(tx *Tx) error {
		r, err := tx.Put("server", "", []byte("web-1"))
		id = r.ID
		if r.Version != 1 {
			t.Fatalf("version %d", r.Version)
		}
		if _, err := tx.Put("server", "", []byte("web-2")); err != nil {
			return err
		}
		_, err2 := tx.Put("secret", "", []byte("pw"))
		return errors.Join(err, err2)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(ctx, func(tx *Tx) error {
		r, err := tx.Put("server", id, []byte("web-1b"))
		if r.Version != 2 {
			t.Fatalf("version %d", r.Version)
		}
		if _, err := tx.Put("secret", id, nil); err == nil {
			t.Fatal("type change accepted")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		r, err := tx.Get(id)
		if err != nil || string(r.Data) != "web-1b" {
			t.Fatalf("get %q %v", r.Data, err)
		}
		l, _ := tx.List("server")
		if len(l) != 2 {
			t.Fatalf("list %d", len(l))
		}
		if _, err := tx.Put("server", "", nil); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("put in view: %v", err)
		}
		if _, err := tx.Get("nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		return nil
	})
	if err := d.Update(ctx, func(tx *Tx) error { return tx.Delete(id) }); err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		r, err := tx.Get(id)
		if err != nil || !r.Deleted || r.Version != 3 || len(r.Data) != 0 {
			t.Fatalf("deleted %+v %v", r, err)
		}
		l, _ := tx.List("server")
		if len(l) != 1 {
			t.Fatalf("list after delete %d", len(l))
		}
		return nil
	})
	if err := d.Update(ctx, func(tx *Tx) error { return tx.Delete("nope") }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestFileHoldsNoPlainText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	_ = d.Update(ctx, func(tx *Tx) error {
		_, err := tx.Put("server", "", []byte("prod-db.example.com"))
		if err == nil {
			err = tx.AppendAudit([]byte("ran uptime on prod-db.example.com"))
		}
		return err
	})
	d.Close()
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte("prod-db")) {
		t.Fatal("plain name in the file")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		t.Fatal("write-ahead log present; want one file")
	}
}

func TestErrorUndoes(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	boom := errors.New("boom")
	err := d.Update(ctx, func(tx *Tx) error {
		if _, err := tx.Put("server", "", []byte("x")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	func() {
		defer func() { _ = recover() }()
		_ = d.Update(ctx, func(tx *Tx) error {
			_, _ = tx.Put("server", "", []byte("y"))
			panic("p")
		})
	}()
	_ = d.View(ctx, func(tx *Tx) error {
		if l, _ := tx.List("server"); len(l) != 0 {
			t.Fatalf("kept %d", len(l))
		}
		return nil
	})
}

func TestWrongKeyAndSwappedRow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	var a, b string
	_ = d.Update(ctx, func(tx *Tx) error {
		ra, _ := tx.Put("server", "", []byte("a"))
		rb, _ := tx.Put("server", "", []byte("b"))
		a, b = ra.ID, rb.ID
		return nil
	})
	d.Close()

	if _, err := Open(ctx, path, key(t, 2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("other key: %v", err)
	}

	// someone with the file swaps the sealed data of two rows
	raw, _ := sql.Open("sqlite", path)
	_, err := raw.Exec(`UPDATE records SET data=(SELECT data FROM records WHERE id=?) WHERE id=?`, b, a)
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}
	d3 := open(t, path)
	err = d3.View(ctx, func(tx *Tx) error { _, err := tx.Get(a); return err })
	if !errors.Is(err, sealrow.ErrOpen) {
		t.Fatalf("swapped row: %v", err)
	}
}

func TestNewerFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	open(t, path).Close()
	raw, _ := sql.Open("sqlite", path)
	_, err := raw.Exec(`UPDATE meta SET v=? WHERE k='format'`, strconv.Itoa(Format+1))
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("newer: %v", err)
	}
}

func TestAudit(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	_ = d.Update(ctx, func(tx *Tx) error {
		for i := range 5 {
			if err := tx.AppendAudit(fmt.Appendf(nil, "e%d", i)); err != nil {
				return err
			}
		}
		return nil
	})
	_ = d.View(ctx, func(tx *Tx) error {
		rows, err := tx.Audit(0, 3)
		if err != nil || len(rows) != 3 || string(rows[0].Data) != "e0" {
			t.Fatalf("%v %v", rows, err)
		}
		rest, _ := tx.Audit(rows[2].Seq, 10)
		if len(rest) != 2 || string(rest[1].Data) != "e4" {
			t.Fatalf("rest %v", rest)
		}
		if err := tx.AppendAudit(nil); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("audit in view: %v", err)
		}
		return nil
	})
}

func TestBackup(t *testing.T) {
	dir := t.TempDir()
	d := open(t, filepath.Join(dir, "store.db"))
	_ = d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err })
	dst := filepath.Join(dir, "copy.db")
	if err := d.Backup(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if err := d.Backup(ctx, dst); err == nil {
		t.Fatal("overwrote a backup")
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", fi.Mode().Perm())
	}
	c := open(t, dst)
	_ = c.View(ctx, func(tx *Tx) error {
		if l, _ := tx.List("server"); len(l) != 1 || string(l[0].Data) != "a" {
			t.Fatalf("backup holds %v", l)
		}
		return nil
	})
}

// TestUniqueAcrossProcesses runs several processes that each add names
// with a read, check and write inside one write step. Every add must land
// once, with no lost update and no duplicate.
func TestUniqueAcrossProcesses(t *testing.T) {
	if p := os.Getenv("SEALDB_CHILD"); p != "" {
		child(t, p, os.Getenv("SEALDB_NAME"))
		return
	}
	path := filepath.Join(t.TempDir(), "store.db")
	open(t, path).Close()
	const procs, each = 4, 15
	cmds := make([]*exec.Cmd, procs)
	for i := range cmds {
		c := exec.Command(os.Args[0], "-test.run=^TestUniqueAcrossProcesses$", "-test.count=1")
		c.Env = append(os.Environ(), "SEALDB_CHILD="+path, "SEALDB_NAME="+strconv.Itoa(i))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = c
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	d := open(t, path)
	_ = d.View(ctx, func(tx *Tx) error {
		l, err := tx.List("server")
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, r := range l {
			if seen[string(r.Data)] {
				t.Fatalf("duplicate %s", r.Data)
			}
			seen[string(r.Data)] = true
		}
		// each child tries "shared" too: it must exist exactly once
		if len(l) != procs*each+1 || !seen["shared"] {
			t.Fatalf("%d records, want %d", len(l), procs*each+1)
		}
		return nil
	})
}

func child(t *testing.T, path, name string) {
	d := open(t, path)
	add := func(n string) error {
		return d.Update(ctx, func(tx *Tx) error {
			l, err := tx.List("server")
			if err != nil {
				return err
			}
			for _, r := range l {
				if string(r.Data) == n {
					return nil
				}
			}
			_, err = tx.Put("server", "", []byte(n))
			return err
		})
	}
	for i := range 15 {
		if err := add(name + "-" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
		if i == 7 {
			if err := add("shared"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTamperedColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	var id string
	_ = d.Update(ctx, func(tx *Tx) error {
		r, err := tx.Put("server", "", []byte("a"))
		id = r.ID
		for i := range 3 {
			if err == nil {
				err = tx.AppendAudit(fmt.Appendf(nil, "e%d", i))
			}
		}
		return err
	})
	d.Close()
	for _, q := range []string{
		`UPDATE records SET deleted=1 WHERE type='server'`,
		`UPDATE records SET mtime=mtime+1 WHERE type='server'`,
	} {
		raw, _ := sql.Open("sqlite", path)
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
		d := open(t, path)
		err := d.View(ctx, func(tx *Tx) error { _, err := tx.Get(id); return err })
		if !errors.Is(err, ErrTampered) {
			t.Fatalf("%s: %v", q, err)
		}
		d.Close()
		raw.Close()
	}
	// audit: an entry removed from the middle, or its time edited
	for _, q := range []string{`DELETE FROM audit WHERE seq=2`, `UPDATE audit SET time=time+1 WHERE seq=1`} {
		p2 := filepath.Join(t.TempDir(), "a.db")
		d := open(t, p2)
		_ = d.Update(ctx, func(tx *Tx) error {
			for i := range 3 {
				if err := tx.AppendAudit(fmt.Appendf(nil, "e%d", i)); err != nil {
					return err
				}
			}
			return nil
		})
		d.Close()
		raw, _ := sql.Open("sqlite", p2)
		_, _ = raw.Exec(q)
		raw.Close()
		d = open(t, p2)
		err := d.View(ctx, func(tx *Tx) error { _, err := tx.Audit(0, 10); return err })
		if !errors.Is(err, ErrTampered) {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestNestedAndOddPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a#b?c%41")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "store.db")
	// an existing file with a wide mode is narrowed
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d := open(t, path)
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	err := d.Update(ctx, func(tx *Tx) error {
		if _, err := tx.Put("server", "", []byte("a")); err != nil {
			return err
		}
		return d.Backup(ctx, filepath.Join(dir, "inside.db"))
	})
	if !errors.Is(err, ErrNested) {
		t.Fatalf("backup inside a step: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "store.db" {
			t.Fatalf("stray file %s: the path was read as a URI", e.Name())
		}
	}
	if err := d.Backup(ctx, filepath.Join(dir, "copy?x.db")); err != nil {
		t.Fatal(err)
	}
	c := open(t, filepath.Join(dir, "copy?x.db"))
	_ = c.View(ctx, func(tx *Tx) error { _, err := tx.List("server"); return err })
}

func TestWrongKeyOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	open(t, path).Close()
	if _, err := Open(ctx, path, key(t, 2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	raw, _ := sql.Open("sqlite", path)
	_, _ = raw.Exec(`DELETE FROM records WHERE id='keycheck'`)
	raw.Close()
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrTampered) {
		t.Fatalf("keycheck removed: %v", err)
	}
}

func TestMetaAndPeek(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	if _, err := Peek(ctx, path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("peek missing: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("peek made the file")
	}
	d := open(t, path)
	err := d.Update(ctx, func(tx *Tx) error {
		if err := tx.SetMeta("format", "9"); err == nil {
			t.Fatal("format set from outside")
		}
		return tx.SetMeta("key_mode", "keyfile")
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		if v, _ := tx.Meta("key_mode"); v != "keyfile" {
			t.Fatalf("meta %q", v)
		}
		if v, _ := tx.Meta("none"); v != "" {
			t.Fatalf("unset meta %q", v)
		}
		if err := tx.SetMeta("a", "b"); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("set in view: %v", err)
		}
		return nil
	})
	m, err := Peek(ctx, path)
	if err != nil || m["key_mode"] != "keyfile" || m["format"] != strconv.Itoa(Format) {
		t.Fatalf("peek %v %v", m, err)
	}
	// the keycheck is a record, but List of other types never shows it
	_ = d.View(ctx, func(tx *Tx) error {
		if l, _ := tx.List("server"); len(l) != 0 {
			t.Fatalf("list %v", l)
		}
		return nil
	})
}

// Goroutines of one process take turns; only a call from inside a step
// is refused.
func TestConcurrentStepsWait(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := d.Update(ctx, func(tx *Tx) error {
				_, err := tx.Put("server", "", []byte(strconv.Itoa(i)))
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	_ = d.View(ctx, func(tx *Tx) error {
		if l, _ := tx.List("server"); len(l) != 16 {
			t.Fatalf("%d records", len(l))
		}
		return nil
	})
}

// A step called from inside a step joins it: a read sees the changes so
// far, a write is a savepoint undone alone on its own error and with the
// outer step on the outer's.
func TestNestedSteps(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	count := func() int {
		n := 0
		_ = d.View(ctx, func(tx *Tx) error { l, _ := tx.List("server"); n = len(l); return nil })
		return n
	}
	boom := errors.New("boom")
	err := d.Update(ctx, func(tx *Tx) error {
		if _, err := tx.Put("server", "", []byte("a")); err != nil {
			return err
		}
		if err := d.View(ctx, func(in *Tx) error {
			if l, _ := in.List("server"); len(l) != 1 {
				t.Fatalf("inner read sees %d", len(l))
			}
			return nil
		}); err != nil {
			return err
		}
		// an inner write that fails is undone alone
		if err := d.Update(ctx, func(in *Tx) error {
			_, _ = in.Put("server", "", []byte("b"))
			return boom
		}); !errors.Is(err, boom) {
			t.Fatalf("inner error: %v", err)
		}
		// an inner write that works stays with the outer
		return d.Update(ctx, func(in *Tx) error {
			_, err := in.Put("server", "", []byte("c"))
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 2 {
		t.Fatalf("%d records, want 2 (a and c)", n)
	}
	// the outer step's error undoes the inner writes too
	_ = d.Update(ctx, func(tx *Tx) error {
		_ = d.Update(ctx, func(in *Tx) error { _, err := in.Put("server", "", []byte("d")); return err })
		return boom
	})
	if n := count(); n != 2 {
		t.Fatalf("%d records after an undone step", n)
	}
	// no change inside a read
	err = d.View(ctx, func(tx *Tx) error {
		return d.Update(ctx, func(*Tx) error { return nil })
	})
	if !errors.Is(err, ErrNested) {
		t.Fatalf("write inside read: %v", err)
	}
}
