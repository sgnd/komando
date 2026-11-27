package vault

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

// A credential that names an item of an outside store (the migration
// makes one from a field that said env:VAR or op://...) reads its value
// from that store, through the same guard as the reference written out.
func TestResolveOutsideCredential(t *testing.T) {
	sealedVault(t)
	t.Setenv("KOMANDO_E1_PW", "value-from-env")
	// what the migration writes for a host that said env:KOMANDO_E1_PW
	d, err := store.DB(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for _, r := range []struct {
			typ string
			v   any
		}{
			{store.KindCredStore, store.CredentialStore{Name: "env", Provider: "env"}},
			{store.KindCredential, store.Credential{Name: "web-credential", Kind: store.CredPassword, User: "app", Store: "env", Item: "KOMANDO_E1_PW"}},
			{store.KindHost, store.HostV3{Name: "web", Address: "10.0.0.5", Provider: "ssh", Credential: "web-credential"}},
		} {
			b, err := json.Marshal(r.v)
			if err != nil {
				return err
			}
			if _, err := tx.Put(r.typ, "", b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	saved := RefGuard
	t.Cleanup(func() { RefGuard = saved })
	RefGuard = func(kind, name string) error {
		asked = append(asked, kind+" "+name)
		return nil
	}
	v, err := Resolve(st.Hosts["web"].PasswordRef)
	if err != nil || v != "value-from-env" {
		t.Fatalf("resolve %s: %q %v", st.Hosts["web"].PasswordRef, v, err)
	}
	if !slices.Contains(asked, "env KOMANDO_E1_PW") {
		t.Fatalf("guard asked %v, want the env variable among them", asked)
	}
	// the guard's no stops it
	RefGuard = func(kind, name string) error { return errors.New("not for you") }
	if _, err := Resolve(st.Hosts["web"].PasswordRef); err == nil || !strings.Contains(err.Error(), "not for you") {
		t.Fatalf("a refused guard: %v", err)
	}
}

// A credential with a value of its own still reads it from the vault.
func TestResolveCredentialValue(t *testing.T) {
	sealedVault(t)
	if err := Set(store.Save(), "db", "pw"); err != nil {
		t.Fatal(err)
	}
	if v, err := Resolve("credential:db"); err != nil || v != "pw" {
		t.Fatalf("resolve %q %v", v, err)
	}
	if _, err := Resolve("credential:none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a missing credential: %v", err)
	}
}

// The spelling of format 2 (secret:NAME) is refused with a usage error
// that names credential:NAME, before anything is read.
func TestResolveRefusesOldSpelling(t *testing.T) {
	sealedVault(t)
	if err := Set(store.Save(), "db", "pw"); err != nil {
		t.Fatal(err)
	}
	saved := RefGuard
	t.Cleanup(func() { RefGuard = saved })
	RefGuard = func(kind, name string) error {
		t.Fatalf("the guard was asked for %s %s", kind, name)
		return nil
	}
	v, err := Resolve("secret:db")
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "REFERENCE_UNSUPPORTED" || !strings.Contains(oe.Hint, "credential:db") || v != "" {
		t.Fatalf("got %q %v, want REFERENCE_UNSUPPORTED naming credential:db", v, err)
	}
	if ValidRef("secret:db") {
		t.Fatal("ValidRef takes the old spelling")
	}
}
