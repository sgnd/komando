package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Rec is a record's identity (docs/design/sync-security.md section 16): a
// random ID that stays when the record is renamed, and a version that goes
// up by one each time the record changes. The coming sealed store keys its
// rows by ID, and sync tells changes apart by version.
//
// A record made before this existed gets its ID on load; it is kept from
// the next saved change on.
type Rec struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

// Kinds of records, as kept in State.IDs.
const (
	KindHost   = "host"
	KindConn   = "conn"
	KindVpn    = "vpn"
	KindKey    = "key"
	KindRecipe = "recipe"
)

// recRef is one record: where its Rec lives and its content.
type recRef struct {
	kind, name string
	rec        *Rec
	v          any
}

func (s *State) recs() []recRef {
	var out []recRef
	for n, h := range s.Hosts {
		out = append(out, recRef{KindHost, n, &h.Rec, h})
	}
	for n, c := range s.Conns {
		out = append(out, recRef{KindConn, n, &c.Rec, c})
	}
	for n, v := range s.Vpns {
		out = append(out, recRef{KindVpn, n, &v.Rec, v})
	}
	for n, k := range s.Keys {
		out = append(out, recRef{KindKey, n, &k.Rec, k})
	}
	for n, r := range s.Snippets {
		out = append(out, recRef{KindRecipe, n, &r.Rec, r})
	}
	return out
}

func newRecID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return hex.EncodeToString(b[:])
}

// loadRecs gives each record its Rec from IDs, and a new one when it has
// none or its ID is already taken (an ID copied by hand to a second record).
func (s *State) loadRecs() {
	seen := map[string]bool{}
	refs := s.recs()
	// names in a fixed order, so which of two records sharing an ID keeps
	// it does not change between loads
	sortRefs(refs)
	for _, r := range refs {
		if m, ok := s.IDs[r.kind][r.name]; ok && m.ID != "" && !seen[m.ID] {
			*r.rec = m
		} else {
			*r.rec = Rec{ID: newRecID(), Version: 1}
		}
		seen[r.rec.ID] = true
	}
}

func sortRefs(refs []recRef) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].kind != refs[j].kind {
			return refs[i].kind < refs[j].kind
		}
		return refs[i].name < refs[j].name
	})
}

// recSnap is a record as it was before a change.
type recSnap struct {
	kind, name string
	rec        Rec
	body       []byte
}

// recSnapshot is each record before a change, by ID.
func (s *State) recSnapshot() map[string]recSnap {
	m := map[string]recSnap{}
	for _, r := range s.recs() {
		b, _ := json.Marshal(r.v)
		m[r.rec.ID] = recSnap{r.kind, r.name, *r.rec, b}
	}
	return m
}

// bumpRecs raises the version of each record that changed since before.
// A renamed record keeps its ID. A record put in place of one with the
// same kind and name (an overwrite) takes that one's ID. Any other new
// record, or a copy that carries another's Rec, gets a new ID.
func (s *State) bumpRecs(before map[string]recSnap) error {
	refs := s.recs()
	sortRefs(refs)
	// who keeps an ID: the record that had it under the same kind and
	// name; else (a rename) the first record holding it
	owner := map[string]int{}
	for pass := range 2 {
		for i, r := range refs {
			old, ok := before[r.rec.ID]
			if !ok || r.rec.ID == "" {
				continue
			}
			if _, taken := owner[r.rec.ID]; taken {
				continue
			}
			if pass == 1 || (old.kind == r.kind && old.name == r.name) {
				owner[r.rec.ID] = i
			}
		}
	}
	gone := map[string]Rec{} // kind/name of records whose ID nobody keeps
	for id, old := range before {
		if _, kept := owner[id]; !kept {
			gone[old.kind+"/"+old.name] = old.rec
		}
	}
	for i, r := range refs {
		if j, ok := owner[r.rec.ID]; ok && j == i {
			b, err := json.Marshal(r.v)
			if err != nil {
				return err
			}
			old := before[r.rec.ID]
			if !bytes.Equal(b, old.body) || old.name != r.name {
				r.rec.Version = old.rec.Version + 1
			}
			continue
		}
		if m, ok := gone[r.kind+"/"+r.name]; ok {
			delete(gone, r.kind+"/"+r.name)
			*r.rec = Rec{ID: m.ID, Version: m.Version + 1}
			continue
		}
		*r.rec = Rec{ID: newRecID(), Version: 1}
	}
	return nil
}

func (s *State) saveRecs() {
	s.IDs = map[string]map[string]Rec{}
	for _, r := range s.recs() {
		if s.IDs[r.kind] == nil {
			s.IDs[r.kind] = map[string]Rec{}
		}
		s.IDs[r.kind][r.name] = *r.rec
	}
}
