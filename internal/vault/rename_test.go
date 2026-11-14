package vault

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// Rename and Copy keep the value inside the vault: it is sealed again under
// the new name (each value is bound to its name), and the old date stays.
func TestRenameAndCopy(t *testing.T) {
	keyfileHome(t)
	if err := Set(store.Save(), "old", "s3cret value"); err != nil {
		t.Fatal(err)
	}
	if err := Set(store.Save(), "other", "x"); err != nil {
		t.Fatal(err)
	}
	before, _ := List()

	if err := Copy(store.Save(), "old", "copy", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename(store.Save(), "old", "new", false); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"copy", "new"} {
		if v, err := Get(n); err != nil || v != "s3cret value" {
			t.Errorf("%s = %q, %v", n, v, err)
		}
	}
	if _, err := Get("old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old is still there: %v", err)
	}
	after, _ := List()
	for _, i := range after {
		if (i.Name == "new" || i.Name == "copy") && !i.UpdatedAt.Equal(before[0].UpdatedAt) {
			t.Errorf("%s: the date changed, the value did not", i.Name)
		}
	}

	// the new name is taken
	if err := Rename(store.Save(), "new", "other", false); !errors.Is(err, ErrExists) {
		t.Errorf("want ErrExists, got %v", err)
	}
	if v, _ := Get("other"); v != "x" {
		t.Errorf("other was replaced without overwrite: %q", v)
	}
	if err := Copy(store.Save(), "new", "other", true); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get("other"); v != "s3cret value" {
		t.Errorf("overwrite: %q", v)
	}
	if err := Rename(store.Save(), "missing", "x", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := Rename(store.Save(), "new", "new", true); err == nil {
		t.Error("renaming to the same name must fail, not delete")
	}

	// the store never holds the value in the clear
	b, _ := os.ReadFile(store.DBPath())
	if strings.Contains(string(b), "s3cret") {
		t.Error("the value is in store.db in the clear")
	}
	f, _ := loadSealed()
	if f == nil || len(f.Entries) != 3 {
		t.Errorf("entries: %d", len(f.Entries))
	}
}

func TestRenameInDryRunChangesNothing(t *testing.T) {
	keyfileHome(t)
	_ = Set(store.Save(), "a", "v")
	if err := Rename(store.Preview(), "a", "b", false); !errors.Is(err, store.ErrDryRun) {
		t.Errorf("want ErrDryRun, got %v", err)
	}
}
