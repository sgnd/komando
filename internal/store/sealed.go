package store

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

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
	if e := PolicyErr(err); e != nil {
		return e
	}
	switch {
	case errors.Is(err, sealdb.ErrNewerFormat), errors.Is(err, sealrow.ErrNewerFormat):
		return out.Errf(out.ExitError, "STORE_NEWER", "a newer komando made or changed this store; update this one: `komando update`",
			"%s was made by a newer komando", Path(StoreFile))
	case errors.Is(err, sealdb.ErrKeyChanged):
		return out.Errf(out.ExitError, "STORE_KEY_CHANGED", "run it again: another komando changed the store's key while this one ran",
			"%s: %v", Path(StoreFile), err)
	case errors.Is(err, sealdb.ErrMetaTampered):
		return out.Errf(out.ExitError, "STATE_CORRUPT",
			"ask the user to run `komando doctor --reseal-meta` in their own terminal: it opens the store with their key, checks that the key opens every record, shows the settings it keeps (key mode, scrypt cost) and seals that row again; if the key does not open the store it changes nothing, and the folder is restored from a backup",
			"%s: its settings row (key mode, salt, scrypt cost) was changed outside komando", Path(StoreFile))
	case errors.Is(err, sealdb.ErrTampered), errors.Is(err, sealdb.ErrWrongKey), errors.Is(err, sealrow.ErrOpen), errors.Is(err, sealdb.ErrBadFormat):
		return out.Errf(out.ExitError, "STATE_CORRUPT",
			"the store does not open with this key or was changed outside komando; ask the user to restore the komando folder from a backup, which then needs the step that accepts an older copy",
			"%s: %v", Path(StoreFile), err)
	}
	return err
}

// loadSealed reads the inventory of a format-3 store from tx into a new
// State (format3_state.go). A reference field that still spells
// secret:NAME stops it (F10).
func loadSealed(tx *sealdb.Tx) (*State, error) {
	s := &State{Settings: DefaultSettings()}
	s.init()
	st, err := readStored3(tx)
	if err != nil {
		return nil, err
	}
	if err := st.checkRefs3(); err != nil {
		return nil, err
	}
	recipes, err := tx.List(KindRecipe)
	if err != nil {
		return nil, err
	}
	if err := st.fillState(s, recipes); err != nil {
		return nil, err
	}
	if err := s.loadMeta(tx); err != nil {
		return nil, err
	}
	s.init()
	s.followIDs()
	return s, nil
}

// loadMeta reads the settings record and the runtime mark from tx.
func (s *State) loadMeta(tx *sealdb.Tx) error {
	rows, err := tx.List(kindSettings)
	if err != nil {
		return err
	}
	switch len(rows) {
	case 0:
	case 1:
		if err := json.Unmarshal(rows[0].Data, &s.Settings); err != nil {
			return err
		}
		s.settingsRec = Rec{ID: rows[0].ID, Version: rows[0].Version}
	default:
		return fmt.Errorf("%d settings records: %w", len(rows), sealdb.ErrTampered)
	}
	if s.runtimeMark, err = readRuntimeMark(tx); err != nil {
		return err
	}
	s.runtimeCopy, err = readRuntimeCopy(tx, s.runtimeMark)
	return err
}

// loadFormat2 reads the inventory of a format-2 store: the migration's
// source only (readFormat2).
func loadFormat2(tx *sealdb.Tx) (*State, error) {
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
	if err := s.loadMeta(tx); err != nil {
		return nil, err
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
		printBefore, err := s.Runtime.sessionPrint()
		if err != nil {
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
		printAfter, err := s.Runtime.sessionPrint()
		if err != nil {
			return err
		}
		if !bytes.Equal(printBefore, printAfter) {
			// the new mark in the same write step as the records
			if s.Runtime.Mark, err = putRuntimeMark(tx); err != nil {
				return err
			}
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
	st, err := readStored3(tx)
	if err != nil {
		return err
	}
	var taken []string
	for n := range st.credID {
		taken = append(taken, n)
	}
	w := &writer3{tx: tx, st: st, names: newNameMaker(taken), ver: map[string]uint64{}}
	kept := map[string]bool{}
	members := map[string][]string{} // entry record ID: its groups
	refs := s.recs()
	sortRefs(refs)
	// keys first: a host names its key credential
	slices.SortStableFunc(refs, func(a, b recRef) int {
		return cmp.Compare(boolInt(a.kind != KindKey), boolInt(b.kind != KindKey))
	})
	for _, r := range refs {
		kept[r.rec.ID] = true
		switch v := r.v.(type) {
		case *Host:
			members[r.rec.ID] = v.Groups
		case *Conn:
			members[r.rec.ID] = v.Groups
		case *Vpn:
			members[r.rec.ID] = v.Groups
		}
		old, had := before[r.rec.ID]
		b, err := json.Marshal(r.v)
		if err != nil {
			return err
		}
		if had && old.kind == r.kind && old.name == r.name && bytes.Equal(old.body, b) {
			r.rec.Version = old.rec.Version // unchanged
			continue
		}
		switch v := r.v.(type) {
		case *Host:
			err = w.host(v)
		case *Conn:
			err = w.conn(v)
		case *Vpn:
			err = w.vpn(v)
		case *Key:
			err = w.key(v)
		case *Snippet:
			_, err = w.put(KindRecipe, r.rec.ID, v)
		}
		if err != nil {
			return err
		}
		if v, ok := w.ver[r.rec.ID]; ok {
			r.rec.Version = v
		}
	}
	for id := range before {
		if !kept[id] {
			if err := tx.Delete(id); err != nil && !errors.Is(err, sealdb.ErrNotFound) {
				return err
			}
			delete(st.hosts, id)
			delete(st.conns, id)
			delete(st.vpns, id)
			members[id] = nil // leaves every group
		}
	}
	if err := w.groups(members); err != nil {
		return err
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

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
