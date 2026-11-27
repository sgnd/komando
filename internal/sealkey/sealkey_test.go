package sealkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var master = bytes.Repeat([]byte{7}, Len)

// Each use has its own label, and so its own key.
func TestLabelsDistinct(t *testing.T) {
	labels := map[Label]bool{}
	keys := map[string]Label{}
	for _, l := range all {
		if labels[l] {
			t.Errorf("label %q is used twice", l)
		}
		labels[l] = true
		k, err := Derive(master, l)
		if err != nil {
			t.Fatal(err)
		}
		if len(k) != Len {
			t.Errorf("%q: %d bytes", l, len(k))
		}
		if bytes.Equal(k, master) {
			t.Errorf("%q gives the master key itself", l)
		}
		if other, ok := keys[string(k)]; ok {
			t.Errorf("%q and %q give the same key", l, other)
		}
		keys[string(k)] = l
	}
	if len(all) != 6 {
		t.Errorf("%d labels, want row (format 2 and 3), runtime, value, ticket and policy", len(all))
	}
}

// The keys komando made before the policy key keep their derivation, so
// runtime.json, secret values and tickets made by an older komando still
// open. The runtime key is what sealed a format-1 store's rows.
func TestOldDerivationsKept(t *testing.T) {
	for l, want := range map[Label]string{
		Runtime: "052611a5687faa707fbda57e02f2757afff695e693b746b53f1eb7d343050b32",
		Values:  "70e0e0ec8eb6a62586417f82cf5160ce9f983071b30bffcbc362d1882e066c2a",
		Tickets: "133978fb825b4b27a007412c5f7ac695971c9a411c2e538d3e3b5fd692582371",
	} {
		k, err := Derive(master, l)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(k); got != want {
			t.Errorf("%q: %s, want %s", l, got, want)
		}
	}
}

// Nothing is made from the row key: the other keys derived from it under
// their own labels are not the real ones.
func TestRowKeyLeadsNowhere(t *testing.T) {
	row, err := Derive(master, Rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range all {
		real, _ := Derive(master, l)
		fromRow, err := Derive(row, l)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(fromRow, real) {
			t.Errorf("%q made from the row key equals the real one", l)
		}
	}
}

func TestDeriveWrongLength(t *testing.T) {
	if _, err := Derive(master[:16], Rows); err == nil {
		t.Error("a 16-byte master key was taken")
	}
}
