package sealdb

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// testPolicy covers a "server" row's mark ("NAME MARK"; no mark, nothing
// covered) and a "pin" row whole.
func testPolicy(t *testing.T, fill byte) *Policy {
	t.Helper()
	p, err := NewPolicy(bytes.Repeat([]byte{fill}, 32), map[string]Part{
		"server": func(b []byte) ([]byte, string, error) {
			name, mark, _ := strings.Cut(string(b), " ")
			if mark == "" {
				return nil, name, nil
			}
			return []byte(mark), name, nil
		},
		"pin": Whole,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// policyStore is a store with a protected server, a plain one, a pin and a
// note, its safety rows under p's MAC, and d checking them.
func policyStore(t *testing.T) (path string, d *DB, p *Policy) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "store.db")
	d = open(t, path)
	p = testPolicy(t, 5)
	err := d.Update(ctx, func(tx *Tx) error {
		for _, r := range [][3]string{{"server", "s1", "web-1 protected"}, {"server", "s2", "web-2"}, {"pin", "p1", "web-1 AAAA"}, {"note", "n1", "hello"}} {
			if _, err := tx.Put(r[0], r[1], []byte(r[2])); err != nil {
				return err
			}
		}
		return tx.SealPolicy(p)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	return path, d, p
}

// rowKeyHandle opens the store as a process given only the row key would:
// it seals rows, but has no policy key.
func rowKeyHandle(t *testing.T, path string) *DB {
	t.Helper()
	o, err := Open(ctx, path, key(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

func rowKeyPut(t *testing.T, path, typ, id, data string) {
	t.Helper()
	err := rowKeyHandle(t, path).Update(ctx, func(tx *Tx) error {
		_, err := tx.Put(typ, id, []byte(data))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyMissing(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "store.db"))
	err := d.SetPolicy(ctx, testPolicy(t, 5))
	if !errors.Is(err, ErrPolicyMissing) || !errors.Is(err, ErrTampered) {
		t.Fatalf("a store without its MAC: %v", err)
	}
}

// A safety row changed with the row key alone stops the next step, which
// names the row.
func TestPolicyTamperRefused(t *testing.T) {
	for _, tc := range []struct {
		name, typ, id, change, label string
		do                           func(t *testing.T, path string)
	}{
		{"mark removed", "server", "s1", "removed", "web-1", func(t *testing.T, path string) { rowKeyPut(t, path, "server", "s1", "web-1") }},
		{"mark added", "server", "s2", "added", "web-2", func(t *testing.T, path string) { rowKeyPut(t, path, "server", "s2", "web-2 protected") }},
		{"marked row added", "server", "s3", "added", "web-3", func(t *testing.T, path string) { rowKeyPut(t, path, "server", "s3", "web-3 protected") }},
		{"pin changed", "pin", "p1", "changed", "", func(t *testing.T, path string) { rowKeyPut(t, path, "pin", "p1", "web-1 BBBB") }},
		{"pin gone", "pin", "p1", "removed", "", func(t *testing.T, path string) {
			err := rowKeyHandle(t, path).Update(ctx, func(tx *Tx) error { return tx.Delete("p1") })
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"MAC from another key", policyType, policyID, "", "", func(t *testing.T, path string) {
			err := rowKeyHandle(t, path).Update(ctx, func(tx *Tx) error { return tx.SealPolicy(testPolicy(t, 6)) })
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, d, _ := policyStore(t)
			tc.do(t, path)
			var pe *PolicyError
			err := d.View(ctx, func(*Tx) error { return nil })
			if !errors.As(err, &pe) || !errors.Is(err, ErrTampered) {
				t.Fatalf("got %v, want a PolicyError", err)
			}
			if pe.Type != tc.typ || pe.ID != tc.id || pe.Change != tc.change || pe.Label != tc.label {
				t.Errorf("got %+v, want %s %s %q %q", *pe, tc.typ, tc.id, tc.change, tc.label)
			}
			if err := d.Update(ctx, func(*Tx) error { return nil }); !errors.As(err, &pe) {
				t.Errorf("a write step went on: %v", err)
			}
		})
	}
}

// A stripped MAC is missing, never made again by a later step.
func TestPolicyStripped(t *testing.T) {
	path, d, _ := policyStore(t)
	err := rowKeyHandle(t, path).Update(ctx, func(tx *Tx) error { return tx.Delete(policyID) })
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Update(ctx, func(*Tx) error { return nil }); !errors.Is(err, ErrPolicyMissing) {
		t.Fatalf("got %v, want ErrPolicyMissing", err)
	}
}

// Rows and parts the MAC does not cover change freely.
func TestPolicyOtherRowsFree(t *testing.T) {
	path, d, _ := policyStore(t)
	rowKeyPut(t, path, "note", "n1", "bye")
	rowKeyPut(t, path, "server", "s2", "web-2b")
	if err := d.View(ctx, func(*Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// A write step through the store's own handle keeps the MAC: the next
// handle with the policy opens it, one without changes it unseen no more.
func TestPolicyLegitWrite(t *testing.T) {
	path, d, p := policyStore(t)
	var before uint64
	_ = d.View(ctx, func(tx *Tx) error {
		r, err := tx.Get(policyID)
		before = r.Version
		return err
	})
	err := d.Update(ctx, func(tx *Tx) error {
		if _, err := tx.Put("server", "s2", []byte("web-2 protected")); err != nil {
			return err
		}
		return tx.Delete("p1")
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = d.View(ctx, func(tx *Tx) error {
		r, err := tx.Get(policyID)
		if err != nil || r.Version != before+1 {
			t.Errorf("MAC record version %d, want %d (%v)", r.Version, before+1, err)
		}
		return nil
	})
	d.Close()
	d2 := rowKeyHandle(t, path)
	if err := d2.SetPolicy(ctx, p); err != nil {
		t.Fatalf("after a legit write: %v", err)
	}
	// a write that touches no safety row leaves the MAC record alone
	if err := d2.Update(ctx, func(tx *Tx) error { return tx.AppendAudit([]byte("x")) }); err != nil {
		t.Fatal(err)
	}
	_ = d2.View(ctx, func(tx *Tx) error {
		if r, _ := tx.Get(policyID); r.Version != before+1 {
			t.Errorf("an audit entry rewrote the MAC (version %d)", r.Version)
		}
		return nil
	})
}

// Upgrade moves a format-1 store to this format: rows under the new key,
// the MAC written once.
func TestUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	CreateFormat = 1 // as an older komando made it
	d := open(t, path)
	CreateFormat = Format
	err := d.Update(ctx, func(tx *Tx) error {
		_, err := tx.Put("server", "s1", []byte("web-1 protected"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	p := testPolicy(t, 5)
	if err := d.Upgrade(ctx, key(t, 2), p); err != nil {
		t.Fatal(err)
	}
	if m, _ := Peek(ctx, path); m["format"] != "2" {
		t.Errorf("format %q after the upgrade", m["format"])
	}
	if err := d.Upgrade(ctx, key(t, 2), p); err == nil {
		t.Error("a second upgrade ran")
	}
	d.Close()
	if _, err := Open(ctx, path, key(t, 1)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("the old row key still opens it: %v", err)
	}
	d2, err := Open(ctx, path, key(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if err := d2.SetPolicy(ctx, p); err != nil {
		t.Fatalf("the upgraded store's MAC: %v", err)
	}
	_ = d2.View(ctx, func(tx *Tx) error {
		if r, err := tx.Get("s1"); err != nil || string(r.Data) != "web-1 protected" {
			t.Errorf("row after the upgrade: %q %v", r.Data, err)
		}
		return nil
	})
}

// Rekey with a new policy key: the MAC is written under it in the same
// step, and the old policy key no longer matches.
func TestRekeyNewPolicy(t *testing.T) {
	path, d, p := policyStore(t)
	p2 := testPolicy(t, 6)
	if err := d.Rekey(ctx, key(t, 2), func(tx *Tx) error { return tx.SealPolicy(p2) }); err != nil {
		t.Fatal(err)
	}
	if err := d.View(ctx, func(*Tx) error { return nil }); err != nil {
		t.Fatalf("after the rekey: %v", err)
	}
	d.Close()
	o, err := Open(ctx, path, key(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	var pe *PolicyError
	if err := o.SetPolicy(ctx, p); !errors.As(err, &pe) || pe.Type != policyType {
		t.Errorf("the old policy key: %v", err)
	}
	if err := o.SetPolicy(ctx, p2); err != nil {
		t.Errorf("the new policy key: %v", err)
	}
}
