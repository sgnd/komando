package store

import (
	"context"
	"errors"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// OutsideRefOf is the reference that the credential name reads its value
// from when it names an item of an outside credential store (env:VAR,
// op://VAULT/ITEM/FIELD...). When the credential does not exist or is not
// such an item: "" and no error.
func OutsideRefOf(name string) (string, error) {
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var ref string
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		st, err := readStored3(tx)
		if err != nil {
			return err
		}
		c := st.cred(name)
		if c == nil || c.Store == "" || c.Item == "" {
			return nil
		}
		if s := st.storeNamed(c.Store); s != nil {
			ref = refFor(s.Provider, c.Item)
		}
		return nil
	})
	return ref, err
}

// storeNamed is the credential store called name, or nil.
func (st *stored3) storeNamed(name string) *CredentialStore {
	for _, s := range st.stores {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// CredentialFix is the one line that says what to do with a field that
// takes a credential and was given anything else, an outside store among
// them (C547, until the credential store paths of C485).
const CredentialFix = "save the secret as a credential with `komando credential password add NAME`, then use credential:NAME"

// CredentialRef checks a reference given as what for a field that names a
// credential (a password, sudo password, key passphrase, VPN key, shared
// key or config). The spelling of format 2 stops with a hint that names
// credential:NAME. An outside reference (env:VAR, op://...) stops too, with
// CredentialFix: no command and no migration makes a credential store item
// for a login (CLI-5, 2026-11-26, confirmed 2026-11-27 in C547; `komando
// credential` in C485 adds them). Empty, credential:NAME and text that is
// no reference at all pass.
func CredentialRef(what, ref string) error {
	if _, old := OldReference(ref); old {
		return OldRefError(what, ref)
	}
	if p, _ := parseRef(ref); p != "" && p != "secret" {
		return out.Errf(out.ExitUsage, "REFERENCE_UNSUPPORTED", CredentialFix,
			"%s names an outside store; it takes credential:NAME", what)
	}
	return nil
}

// refCred is the credential a reference field of entry names
// (credential:NAME), after CredentialRef.
func refCred(entry, field, ref string) (string, error) {
	if err := CredentialRef(entry+": field "+field, ref); err != nil {
		return "", err
	}
	return credOfRef(entry, field, ref)
}

// refuseOldRefs is the F10 check on a record before it is written: a
// write never leaves a store that its next load refuses.
func refuseOldRefs(entry string, rec any) error {
	for _, f := range refFields3(rec) {
		if _, old := OldReference(f.value); old {
			return OldRefError(entry+": field "+f.field, f.value)
		}
	}
	return nil
}
