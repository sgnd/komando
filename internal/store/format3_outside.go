package store

import (
	"context"
	"errors"
	"strconv"

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

// storeFor is the credential store of provider: the first one the store
// has, or a new one named after the provider, as the migration makes it.
func (w *writer3) storeFor(provider string) (string, error) {
	names := map[string]bool{}
	for _, s := range w.st.stores {
		if s.Provider == provider {
			return s.Name, nil
		}
		names[s.Name] = true
	}
	name := provider
	for i := 2; names[name]; i++ {
		name = provider + "-" + strconv.Itoa(i)
	}
	s := &CredentialStore{Name: name, Provider: provider}
	id, err := w.put(KindCredStore, "", s)
	if err != nil {
		return "", err
	}
	w.st.stores[id] = s
	return name, nil
}

// refCred is the credential a reference field of entry names: the name in
// credential:NAME; for an outside reference (env:VAR, op://...), the
// credential the field names now when it reads that same item, else a new
// one in the store of that provider, named <base>-<part> as the migration
// names it. The spelling of format 2 and any other text stop.
func (w *writer3) refCred(entry, field, base, part, kind, ref, current string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if _, old := OldReference(ref); old {
		return "", OldRefError(entry+": field "+field, ref)
	}
	provider, item := parseRef(ref)
	if provider == "" || provider == "secret" {
		return credOfRef(entry, field, ref)
	}
	if c := w.st.cred(current); c != nil && c.Item == item && c.Value == nil {
		if s := w.st.storeNamed(c.Store); s != nil && s.Provider == provider {
			return current, nil
		}
	}
	store, err := w.storeFor(provider)
	if err != nil {
		return "", err
	}
	return w.newCred(base, part, &Credential{Kind: kind, Store: store, Item: item})
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
