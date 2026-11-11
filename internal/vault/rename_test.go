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
	if err := Set("old", "s3cret value"); err != nil {
		t.Fatal(err)
	}
	if err := Set("other", "x"); err != nil {
		t.Fatal(err)
	}
	before, _ := List()

	if err := Copy("old", "copy", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename("old", "new", false); err != nil {
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
	if err := Rename("new", "other", false); !errors.Is(err, ErrExists) {
		t.Errorf("want ErrExists, got %v", err)
	}
	if v, _ := Get("other"); v != "x" {
		t.Errorf("other was replaced without overwrite: %q", v)
	}
	if err := Copy("new", "other", true); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get("other"); v != "s3cret value" {
		t.Errorf("overwrite: %q", v)
	}
	if err := Rename("missing", "x", false); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := Rename("new", "new", true); err == nil {
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
	_ = Set("a", "v")
	store.DryRun = true
	defer func() { store.DryRun = false }()
	if err := Rename("a", "b", false); !errors.Is(err, store.ErrDryRun) {
		t.Errorf("want ErrDryRun, got %v", err)
	}
}
