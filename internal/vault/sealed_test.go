package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func sealedVault(t *testing.T) {
	t.Helper()
	freshHome(t)
	store.UseSealedForNewHomes(true)
	t.Cleanup(func() { store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1") })
}

func TestSealedVault(t *testing.T) {
	sealedVault(t)
	if l, err := List(); err != nil || len(l) != 0 {
		t.Fatalf("empty: %v %v", l, err)
	}
	if s, err := Check(); err != nil || !s.NoVaultYet {
		t.Fatalf("check before: %+v %v", s, err)
	}
	for k, v := range map[string]string{"db": "s3cret-value", "api": "tok-123", "old": "x"} {
		if err := Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := Get("db"); err != nil || v != "s3cret-value" {
		t.Fatalf("get %q %v", v, err)
	}
	if err := Set("db", "changed"); err != nil {
		t.Fatal(err)
	}
	if v, _ := Get("db"); v != "changed" {
		t.Fatalf("after change %q", v)
	}
	if err := Delete("old"); err != nil {
		t.Fatal(err)
	}
	if _, err := Get("old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if err := Copy("api", "api2", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename("api2", "api3", false); err != nil {
		t.Fatal(err)
	}
	if err := Rename("api", "db", false); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto a name: %v", err)
	}
	if err := RenameMany(map[string]string{"api3": "api4"}); err != nil {
		t.Fatal(err)
	}
	l, _ := List()
	var names []string
	for _, i := range l {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "api,api4,db" {
		t.Fatalf("names %v", names)
	}
	if v, _ := Get("api4"); v != "tok-123" {
		t.Fatalf("renamed value %q", v)
	}
	// no vault.json, nothing readable in the store, and the mode is the
	// store's own
	for _, f := range []string{"vault.json", "vault.key"} {
		if _, err := os.Stat(store.Path(f)); !os.IsNotExist(err) {
			t.Fatalf("%s written in a sealed home", f)
		}
	}
	b, _ := os.ReadFile(store.Path(store.StoreFile))
	for _, w := range []string{"changed", "tok-123", "api4"} {
		if strings.Contains(string(b), w) {
			t.Fatalf("%q readable in store.db", w)
		}
	}
	if s, err := Check(); err != nil || s.Mode != "keyfile" {
		t.Fatalf("check %+v %v", s, err)
	}
	if _, err := ChangeKey("", "a passphrase long enough"); !errors.Is(err, errSealedKeyChange) {
		t.Fatalf("key change: %v", err)
	}
	if err := KeyToFile(); !errors.Is(err, errSealedKeyChange) {
		t.Fatalf("key move: %v", err)
	}
}

func TestSealedVaultParallel(t *testing.T) {
	sealedVault(t)
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Set(fmt.Sprintf("s%d", i), "v"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if l, _ := List(); len(l) != 12 {
		t.Fatalf("%d secrets, want 12", len(l))
	}
}

// The inventory and the vault share the store; a secret set beside a
// server change keeps both.
func TestSealedVaultBesideInventory(t *testing.T) {
	sealedVault(t)
	if err := store.Update(func(s *store.State) error {
		s.Hosts["web"] = &store.Host{Name: "web", PasswordRef: "secret:db"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := Set("db", "pw"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil || st.Hosts["web"] == nil {
		t.Fatalf("inventory lost: %v", err)
	}
	if v, err := Resolve("secret:db"); err != nil || v != "pw" {
		t.Fatalf("resolve %q %v", v, err)
	}
}
