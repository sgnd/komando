package sealdb

import (
	"errors"
	"testing"
)

// migrateStore is policyStore with three audit entries.
func migrateStore(t *testing.T) (string, *DB, *Policy) {
	t.Helper()
	path, d, p := policyStore(t)
	err := d.Update(ctx, func(tx *Tx) error {
		for _, e := range []string{"a", "b", "c"} {
			if err := tx.AppendAudit([]byte(e)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return path, d, p
}

// formatOf reads the store's format without a key.
func formatOf(t *testing.T, path string) string {
	t.Helper()
	m, err := Peek(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return m["format"]
}

func TestMigrate(t *testing.T) {
	path, d, p := migrateStore(t)
	var seen []string
	err := d.Migrate(ctx, Format, Format+1, key(t, 2), p,
		func(tx *Tx) error {
			_, err := tx.Put("credential", "", []byte("db-pass"))
			return err
		},
		func(tx *Tx) error {
			for _, typ := range []string{"server", "pin", "note", "credential"} {
				rs, err := tx.List(typ)
				if err != nil {
					return err
				}
				for _, r := range rs {
					seen = append(seen, string(r.Data))
				}
			}
			rows, err := tx.Audit(0, 10)
			if err == nil && len(rows) != 3 {
				return errors.New("audit entries lost")
			}
			return err
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Errorf("read back %d records under the new key: %q", len(seen), seen)
	}
	if f := formatOf(t, path); f != "3" {
		t.Errorf("format %s after the migration", f)
	}
	if err := d.Update(ctx, func(*Tx) error { return nil }); err == nil {
		t.Error("the handle that migrated still writes in the old format")
	}
	// an older komando cannot open it; the new row key is in force
	if _, err := Open(ctx, path, key(t, 2)); !errors.Is(err, ErrNewerFormat) {
		t.Errorf("an older komando opens the migrated store: %v", err)
	}
}

// Every failure leaves the store as it was: format 2, the old row key, the
// same records.
func TestMigrateFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(t *testing.T, path string)
		change func(*Tx) error
		verify func(*Tx) error
		want   error
	}{
		{
			name: "a safety row changed by the migration",
			change: func(tx *Tx) error {
				rs, err := tx.List("server")
				if err != nil {
					return err
				}
				for _, r := range rs {
					if string(r.Data) == "web-1 protected" {
						_, err = tx.Put("server", r.ID, []byte("web-1"))
					}
				}
				return err
			},
			want: ErrSafetyChanged,
		},
		{
			name: "a broken audit chain",
			setup: func(t *testing.T, path string) {
				db := rawDB(t, path)
				if _, err := db.Exec(`DELETE FROM audit WHERE seq=2`); err != nil {
					t.Fatal(err)
				}
			},
			want: ErrTampered,
		},
		{
			name:   "the read-back fails",
			verify: func(*Tx) error { return errBoom },
			want:   errBoom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, d, p := migrateStore(t)
			if tt.setup != nil {
				tt.setup(t, path)
			}
			change, verify := tt.change, tt.verify
			if change == nil {
				change = func(*Tx) error { return nil }
			}
			if verify == nil {
				verify = func(*Tx) error { return nil }
			}
			err := d.Migrate(ctx, Format, Format+1, key(t, 2), p, change, verify)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got %v", tt.want, err)
			}
			if f := formatOf(t, path); f != "2" {
				t.Errorf("format %s after a failed migration", f)
			}
			o := rowKeyHandle(t, path) // the old row key still opens it
			err = o.View(ctx, func(tx *Tx) error {
				rs, err := tx.List("server")
				if err == nil && len(rs) != 2 {
					err = errors.New("servers lost")
				}
				return err
			})
			if err != nil {
				t.Error(err)
			}
		})
	}
}

var errBoom = errors.New("boom")

// A migration seals a new policy MAC only over rows the store's own MAC
// was checked against (Audit M4).
func TestMigrateNeedsCheckedPolicy(t *testing.T) {
	path, d, p := migrateStore(t)
	d.Close()
	o := rowKeyHandle(t, path) // opened without SetPolicy
	err := o.Migrate(ctx, Format, Format+1, key(t, 2), p, func(*Tx) error { return nil }, func(*Tx) error { return nil })
	if !errors.Is(err, ErrPolicyMissing) {
		t.Fatalf("want ErrPolicyMissing, got %v", err)
	}
	if f := formatOf(t, path); f != "2" {
		t.Errorf("format %s", f)
	}
}

func TestMigrateWrongFrom(t *testing.T) {
	path, d, p := migrateStore(t)
	if err := d.Migrate(ctx, 1, 3, key(t, 2), p, func(*Tx) error { return nil }, func(*Tx) error { return nil }); err == nil {
		t.Fatal("a store of format 2 migrated as format 1")
	}
	if f := formatOf(t, path); f != "2" {
		t.Errorf("format %s", f)
	}
}
