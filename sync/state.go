package komandosync

import (
	"bytes"
	"cmp"
	"maps"
	"slices"
)

// The one byte form of a merged state, which a snapshot seals (SS 9).

// encode is the one byte form of the state at heads, the same on every
// device that merged the same writes: records by ID with their fields by
// name, waiting changes by write, the yeses whose change is not among the
// writes yet, and the waiting changes a yes set aside. A deleted record
// keeps only its type and its name: its marker goes, its deletion stays
// final.
func (m *mergeState) encode(heads map[DeviceID]Head) []byte {
	var e enc
	ids := slices.SortedFunc(maps.Keys(m.records), func(a, b RecordID) int { return bytes.Compare(a[:], b[:]) })
	e.u32(uint32(len(ids)))
	for _, id := range ids {
		r := m.records[id]
		e.raw(id[:])
		e.str(r.Type)
		e.bool(r.Exists)
		e.bool(r.Deleted)
		names := slices.Sorted(maps.Keys(r.Fields))
		if r.Deleted {
			names = slices.DeleteFunc(names, func(n string) bool { return n != "name" })
		}
		e.u32(uint32(len(names)))
		for _, n := range names {
			f := r.Fields[n]
			e.str(n)
			e.str(f.Value)
			encodeClock(&e, f.Clock)
		}
	}
	refs := slices.SortedFunc(maps.Keys(m.waiting), cmpRef)
	e.u32(uint32(len(refs)))
	for _, ref := range refs {
		w := m.waiting[ref]
		encodeRef(&e, ref)
		e.raw(w.Record[:])
		e.str(w.Type)
		e.bool(w.Create)
		e.bool(w.Delete)
		e.u32(uint32(len(w.Fields)))
		for _, f := range w.Fields {
			e.str(f.Name)
			e.str(f.Value)
		}
		encodeClock(&e, w.Clock)
	}
	// Yeses whose change is not among the writes yet, with the record each
	// names.
	var ok []approval
	for ap := range m.approved {
		if ap.Ref.Seq > heads[ap.Ref.Writer].Seq {
			ok = append(ok, ap)
		}
	}
	slices.SortFunc(ok, func(a, b approval) int {
		return cmp.Or(cmpRef(a.Ref, b.Ref), cmpRecord(a.Record, b.Record))
	})
	e.u32(uint32(len(ok)))
	for _, ap := range ok {
		encodeRef(&e, ap.Ref)
		e.raw(ap.Record[:])
	}
	// Waiting changes a yes set aside, while they can still matter: the
	// change waits here, or is not among the writes yet.
	var out []withdrawal
	for wd := range m.withdrawn {
		if m.waiting[wd.Ref] != nil || wd.Ref.Seq > heads[wd.Ref.Writer].Seq {
			out = append(out, wd)
		}
	}
	slices.SortFunc(out, func(a, b withdrawal) int {
		return cmp.Or(cmpRef(a.Ref, b.Ref), cmp.Compare(a.Type, b.Type))
	})
	e.u32(uint32(len(out)))
	for _, wd := range out {
		encodeRef(&e, wd.Ref)
		e.str(wd.Type)
	}
	return e.b
}

func encodeRef(e *enc, r WriteRef) {
	e.raw(r.Writer[:])
	e.u64(r.Seq)
	e.raw(r.Hash[:])
}

func encodeClock(e *enc, c HLC) {
	e.u64(uint64(c.Wall))
	e.u32(c.Count)
	e.raw(c.Dev[:])
}

func decodeRef(d *dec) WriteRef {
	var r WriteRef
	d.fixed(r.Writer[:])
	r.Seq = d.u64()
	d.fixed(r.Hash[:])
	return r
}

func decodeClock(d *dec) HLC {
	c := HLC{Wall: int64(d.u64()), Count: d.u32()}
	d.fixed(c.Dev[:])
	return c
}

// decodeState reads what encode wrote.
func decodeState(b []byte) (*mergeState, error) {
	d := dec{b: b}
	m := newMergeState()
	for range d.count(1 << 20) {
		var id RecordID
		d.fixed(id[:])
		r := &record{Type: d.str(), Exists: d.bool(), Deleted: d.bool(), Fields: map[string]fieldVal{}}
		for range d.count(4096) {
			n := d.str()
			r.Fields[n] = fieldVal{Value: d.str(), Clock: decodeClock(&d)}
		}
		m.records[id] = r
	}
	for range d.count(1 << 20) {
		ref := decodeRef(&d)
		w := &waiting{Ref: ref}
		d.fixed(w.Record[:])
		w.Type = d.str()
		w.Create = d.bool()
		w.Delete = d.bool()
		for range d.count(4096) {
			w.Fields = append(w.Fields, Field{Name: d.str(), Value: d.str()})
		}
		w.Clock = decodeClock(&d)
		m.waiting[ref] = w
	}
	for range d.count(1 << 20) {
		ap := approval{Ref: decodeRef(&d)}
		d.fixed(ap.Record[:])
		m.approved[ap] = true
	}
	for range d.count(1 << 20) {
		wd := withdrawal{Ref: decodeRef(&d)}
		wd.Type = d.str()
		m.withdrawn[wd] = true
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// clone is a deep copy.
func (m *mergeState) clone() *mergeState {
	c := newMergeState()
	for id, r := range m.records {
		c.records[id] = &record{Type: r.Type, Fields: maps.Clone(r.Fields), Exists: r.Exists, Deleted: r.Deleted}
	}
	for ref, w := range m.waiting {
		cw := *w
		cw.Fields = slices.Clone(w.Fields)
		c.waiting[ref] = &cw
	}
	maps.Copy(c.approved, m.approved)
	maps.Copy(c.withdrawn, m.withdrawn)
	maps.Copy(c.markers, m.markers)
	return c
}
