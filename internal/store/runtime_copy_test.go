package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
)

// hasRuntimeCopy reports whether store.db still holds the migration's
// copy of the runtime records.
func hasRuntimeCopy(t *testing.T) bool {
	t.Helper()
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get(runtimeCopyID)
		if errors.Is(err, sealdb.ErrNotFound) {
			return nil
		}
		found = err == nil && !r.Deleted
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// Q7a: a migration that ends cleanly leaves no copy of the runtime
// records in the store; runtime.json holds them.
func TestRuntimeCopyGoneAfterMigration(t *testing.T) {
	format2Store(t)
	format2Runtime(t, func(s *State) {
		s.ExecSessions["e1"] = &ExecSession{ID: "e1", Host: "web1", Command: "sleep 1", PID: 42}
	})
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatal(err)
	}
	Close()
	if hasRuntimeCopy(t) {
		t.Error("the runtime copy is still in the store")
	}
	rt, err := ReadRuntime()
	if err != nil || rt.ExecSessions["e1"] == nil {
		t.Fatalf("runtime after the migration: %+v %v", rt, err)
	}
}

// Q7b: the copy is used only when its mark is the store's mark and
// runtime.json's is not; it never overrides a runtime.json that matches.
func TestRuntimeCopyNeverOverridesNewer(t *testing.T) {
	migrated(t)
	rt, err := ReadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	put := func(mark string) {
		format3Write(t, func(tx *sealdb.Tx) error {
			b, _ := json.Marshal(runtimeCopy{Mark: mark, ExecSessions: map[string]*ExecSession{"stale": {ID: "stale", Host: "old"}}})
			_, err := tx.Put(kindRuntimeCopy, runtimeCopyID, b)
			return err
		})
	}
	for name, mark := range map[string]string{"an old mark": "0000", "the store's mark, beside a runtime.json that matches": rt.Mark} {
		t.Run(name, func(t *testing.T) {
			put(mark)
			got, err := ReadRuntime()
			if err != nil {
				t.Fatal(err)
			}
			if got.ExecSessions["stale"] != nil {
				t.Error("the copy overrode a runtime.json that matches the store")
			}
		})
	}
}
