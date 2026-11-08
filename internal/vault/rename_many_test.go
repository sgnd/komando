package vault

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// RenameMany moves every secret in one change, keeps each value and its
// date, and refuses what could hand one secret's value to another name.
func TestRenameMany(t *testing.T) {
	keyfileHome(t)
	for n, v := range map[string]string{"shop-db": "db pass", "shop-vpn": "vpn psk", "other": "x"} {
		if err := Set(n, v); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := List()
	if err := RenameMany(map[string]string{"shop-db": "acme-shop-db", "shop-vpn": "acme-shop-vpn"}); err != nil {
		t.Fatal(err)
	}
	for n, v := range map[string]string{"acme-shop-db": "db pass", "acme-shop-vpn": "vpn psk", "other": "x"} {
		if got, err := Get(n); err != nil || got != v {
			t.Errorf("%s = %q, %v", n, got, err)
		}
	}
	for _, n := range []string{"shop-db", "shop-vpn"} {
		if _, err := Get(n); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s is still there: %v", n, err)
		}
	}
	after, _ := List()
	for _, i := range after {
		if i.Name == "acme-shop-db" && !i.UpdatedAt.Equal(before[1].UpdatedAt) { // before is sorted: other, shop-db, shop-vpn
			t.Errorf("the date changed, the value did not")
		}
	}
	if err := RenameMany(nil); err != nil {
		t.Errorf("nothing to rename: %v", err)
	}

	// refused, and the vault file stays byte for byte
	vaultFile := func() []byte { b, _ := os.ReadFile(vaultPath()); return b }
	keep := vaultFile()
	for name, pairs := range map[string]map[string]string{
		"target exists":    {"acme-shop-db": "other"},
		"swap":             {"acme-shop-db": "acme-shop-vpn", "acme-shop-vpn": "acme-shop-db"},
		"chain":            {"acme-shop-db": "acme-shop-vpn", "acme-shop-vpn": "z"},
		"two into one":     {"acme-shop-db": "z", "acme-shop-vpn": "z"},
		"missing source":   {"nope": "z", "acme-shop-db": "y"},
		"same name":        {"other": "other"},
		"empty name":       {"other": ""},
		"reserved source":  {reservedName: "z"},
		"reserved target":  {"other": reservedName},
		"one bad of three": {"acme-shop-db": "a", "acme-shop-vpn": "b", "other": "acme-shop-db"},
	} {
		if err := RenameMany(pairs); err == nil {
			t.Errorf("%s: no error", name)
		}
		if !bytes.Equal(vaultFile(), keep) {
			t.Fatalf("%s: the vault changed", name)
		}
	}
	if err := RenameMany(map[string]string{"acme-shop-db": "other"}); !errors.Is(err, ErrExists) {
		t.Errorf("want ErrExists, got %v", err)
	}
	if err := RenameMany(map[string]string{"nope": "z"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
	if err := RenameMany(map[string]string{"other": reservedName}); err == nil || !strings.Contains(err.Error(), "approval code") {
		t.Errorf("reserved: %v", err)
	}
}
