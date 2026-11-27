// Package sealkey makes each of the store's keys from its master key:
// HKDF-SHA256 with no salt and one label per use. Every key comes from the
// master key alone, never from another key, so whoever holds one of them
// (the row key, say) can make none of the others.
//
// The package holds no key and reads no file or environment.
package sealkey

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// Len is the size of the master key and of every key made from it.
const Len = 32

// Label names one key made from the master key.
type Label string

const (
	// Rows seals the records and audit entries of a format-2 store.db;
	// only the migration to format 3 reads it.
	Rows Label = "komando local store v2"
	// RowsV3 seals the records and audit entries of store.db (format 3).
	RowsV3 Label = "komando local store v3"
	// Runtime seals runtime.json. It is the derivation a format-1 store
	// sealed its rows with, so it also opens such a store to upgrade it.
	Runtime Label = "komando local store v1"
	// Values seals each secret value inside its record.
	Values Label = "komando vault entries v1"
	// Tickets signs the tickets of komando's background commands.
	Tickets Label = "komando spawn tickets v1"
	// Policy signs the store's safety rows (sealdb's policy MAC).
	Policy Label = "komando policy v1"
)

// all is every label; no two may be the same.
var all = []Label{Rows, RowsV3, Runtime, Values, Tickets, Policy}

// Derive makes the key for l from master.
func Derive(master []byte, l Label) ([]byte, error) {
	if len(master) != Len {
		return nil, fmt.Errorf("sealkey: master key is %d bytes, want %d", len(master), Len)
	}
	return hkdf.Key(sha256.New, master, nil, string(l), Len)
}
