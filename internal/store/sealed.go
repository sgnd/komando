package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
)

// The inventory in the sealed store: one record per server, conn, VPN,
// key and recipe (the kinds of rec.go, as record types), and one for the
// settings. Each record holds the struct's JSON; its ID and version are
// the row's.

const kindSettings = "settings"

func storeErr(err error) error {
	switch {
	case errors.Is(err, sealdb.ErrNewerFormat), errors.Is(err, sealrow.ErrNewerFormat):
		return out.Errf(out.ExitError, "STORE_NEWER", "a newer komando made or changed this store; update this one: `komando update`",
			"%s was made by a newer komando", Path(StoreFile))
	case errors.Is(err, sealdb.ErrKeyChanged):
		return out.Errf(out.ExitError, "STORE_KEY_CHANGED", "run it again: another komando changed the store's key while this one ran",
			"%s: %v", Path(StoreFile), err)
	case errors.Is(err, sealdb.ErrTampered), errors.Is(err, sealdb.ErrWrongKey), errors.Is(err, sealrow.ErrOpen):
		return out.Errf(out.ExitError, "STATE_CORRUPT",
			"the store does not open with this key or was changed outside komando; ask the user to restore the komando folder from a backup, which then needs the step that accepts an older copy",
			"%s: %v", Path(StoreFile), err)
	}
	return err
}

// loadSealed reads the inventory from tx into a new State.
func loadSealed(tx *sealdb.Tx) (*State, error) {
	s := &State{Settings: DefaultSettings()}
	s.init()
	put := func(kind string, r sealdb.Record) error {
		var name string
		var rec *Rec
		switch kind {
		case KindHost:
			v := &Host{}
			if err := json.Unmarshal(r.Data, v); err != nil {
				return err
			}
			if s.Hosts[v.Name] != nil {
				return dupName(kind, v.Name)
			}
			s.Hosts[v.Name], name, rec = v, v.Name, &v.Rec
		case KindConn:
			v := &Conn{}
			if err := json.Unmarshal(r.Data, v); err != nil {
				return err
			}
			if s.Conns[v.Name] != nil {
				return dupName(kind, v.Name)
			}
			s.Conns[v.Name], name, rec = v, v.Name, &v.Rec
		case KindVpn:
			v := &Vpn{}
			if err := json.Unmarshal(r.Data, v); err != nil {
				return err
			}
			if s.Vpns[v.Name] != nil {
				return dupName(kind, v.Name)
			}
			s.Vpns[v.Name], name, rec = v, v.Name, &v.Rec
		case KindKey:
			v := &Key{}
			if err := json.Unmarshal(r.Data, v); err != nil {
				return err
			}
			if s.Keys[v.Name] != nil {
				return dupName(kind, v.Name)
			}
			s.Keys[v.Name], name, rec = v, v.Name, &v.Rec
		case KindRecipe:
			v := &Snippet{}
			if err := json.Unmarshal(r.Data, v); err != nil {
				return err
			}
			if s.Snippets[v.Name] != nil {
				return dupName(kind, v.Name)
			}
			s.Snippets[v.Name], name, rec = v, v.Name, &v.Rec
		}
		if name == "" {
			return fmt.Errorf("a %s record without a name: %w", kind, sealdb.ErrTampered)
		}
		*rec = Rec{ID: r.ID, Version: r.Version}
		return nil
	}
	for _, kind := range []string{KindHost, KindConn, KindVpn, KindKey, KindRecipe} {
		rows, err := tx.List(kind)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if err := put(kind, r); err != nil {
				return nil, err
			}
		}
	}
	rows, err := tx.List(kindSettings)
	if err != nil {
		return nil, err
	}
	switch len(rows) {
	case 0:
	case 1:
		if err := json.Unmarshal(rows[0].Data, &s.Settings); err != nil {
			return nil, err
		}
		s.settingsRec = Rec{ID: rows[0].ID, Version: rows[0].Version}
	default:
		return nil, fmt.Errorf("%d settings records: %w", len(rows), sealdb.ErrTampered)
	}
	s.init()      // defaults for settings the record does not set
	s.followIDs() // a rename made elsewhere reaches the references (refs.go)
	return s, nil
}

func dupName(kind, name string) error {
	return fmt.Errorf("two %s records named %q: %w", kind, name, sealdb.ErrTampered)
}

// Load reads the inventory. Callers that change it use Update.
func Load() (*State, error) {
	// the folder, as before; never the store or a key
	if err := ensureHome(); err != nil {
		return nil, err
	}
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		s := &State{Settings: DefaultSettings()}
		s.init()
		return s, s.loadRuntime()
	}
	if err != nil {
		return nil, storeErr(err)
	}
	var s *State
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		var err error
		s, err = loadSealed(tx)
		return err
	})
	if err != nil {
		return nil, storeErr(err)
	}
	return s, s.loadRuntime()
}

// updateStore is Update: one write step reads the
// inventory, runs fn and writes the records that changed.
func updateStore(fn func(*State) error) error {
	if err := ensureHome(); err != nil {
		return err
	}
	// the runtime lock first, then the store's: UpdateRuntime takes them
	// in the same order
	unlockRT, err := Lock(runtimeLock)
	if err != nil {
		return err
	}
	defer unlockRT()
	d, err := DB(true)
	if err != nil {
		return storeErr(err)
	}
	var s *State
	var rtBefore []byte
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		var err error
		if s, err = loadSealed(tx); err != nil {
			return err
		}
		if err := s.loadRuntime(); err != nil {
			return err
		}
		if rtBefore, err = json.Marshal(&s.Runtime); err != nil {
			return err
		}
		before := s.recSnapshot()
		setBefore, err := json.Marshal(&s.Settings)
		if err != nil {
			return err
		}
		if err := fn(s); err != nil {
			return err
		}
		return s.writeSealed(tx, before, setBefore)
	})
	if err != nil {
		var oe *out.Error
		if errors.As(err, &oe) {
			return err
		}
		return storeErr(err)
	}
	rtAfter, err := json.Marshal(&s.Runtime)
	if err != nil {
		return err
	}
	if !bytes.Equal(rtBefore, rtAfter) {
		return s.saveRuntime()
	}
	return nil
}

// writeSealed writes what fn changed: new and changed records at their
// next version, removed records as deletions. IDs follow the rules of
// bumpRecs (a rename keeps its ID, an overwrite takes the old one).
func (s *State) writeSealed(tx *sealdb.Tx, before map[string]recSnap, setBefore []byte) error {
	if err := s.bumpRecs(before); err != nil {
		return err
	}
	s.followNames() // every reference's ID from its name, new records too (refs.go)
	kept := map[string]bool{}
	for _, r := range s.recs() {
		kept[r.rec.ID] = true
		old, had := before[r.rec.ID]
		b, err := json.Marshal(r.v)
		if err != nil {
			return err
		}
		if had && old.kind == r.kind && old.name == r.name && bytes.Equal(old.body, b) {
			r.rec.Version = old.rec.Version // unchanged
			continue
		}
		rec, err := tx.Put(r.kind, r.rec.ID, b)
		if err != nil {
			return err
		}
		r.rec.Version = rec.Version
	}
	for id := range before {
		if !kept[id] {
			if err := tx.Delete(id); err != nil && !errors.Is(err, sealdb.ErrNotFound) {
				return err
			}
		}
	}
	b, err := json.Marshal(&s.Settings)
	if err != nil {
		return err
	}
	if s.settingsRec.ID == "" || !bytes.Equal(b, setBefore) {
		rec, err := tx.Put(kindSettings, s.settingsRec.ID, b)
		if err != nil {
			return err
		}
		s.settingsRec = Rec{ID: rec.ID, Version: rec.Version}
	}
	return nil
}
