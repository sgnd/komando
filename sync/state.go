package komandosync

import (
	"bytes"
	"maps"
	"slices"
)

// The one byte form of a merged state, which a snapshot seals (SS 9).

// encode is the one byte form of the state at heads, the same on every
// device that merged the same writes: records by ID with their fields by
// name, waiting changes by write, and the approvals whose change is not
// among the writes yet. A deleted record keeps only its type and its
// name: its marker goes, its deletion stays final.
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
	var ok []WriteRef
	for ref := range m.approved {
		if ref.Seq > heads[ref.Writer].Seq {
			ok = append(ok, ref)
		}
	}
	slices.SortFunc(ok, cmpRef)
	e.u32(uint32(len(ok)))
	for _, ref := range ok {
		encodeRef(&e, ref)
		e.u32(uint32(len(m.replaces[ref])))
		for _, id := range m.replaces[ref] {
			e.raw(id[:])
		}
	}
	// Approved changes that set a name and applied, with the union of
	// their approvals' old holders: a yes that arrives later deletes the
	// holders it adds on every device, rebuilt from a snapshot or not.
	done := slices.SortedFunc(maps.Keys(m.done), cmpRef)
	e.u32(uint32(len(done)))
	for _, ref := range done {
		w := m.done[ref]
		encodeRef(&e, ref)
		e.raw(w.Record[:])
		e.str(w.Type)
		e.u32(uint32(len(m.replaces[ref])))
		for _, id := range m.replaces[ref] {
			e.raw(id[:])
		}
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
		ref := decodeRef(&d)
		m.approved[ref] = true
		var ids []RecordID
		for range d.count(4096) {
			var id RecordID
			d.fixed(id[:])
			ids = append(ids, id)
		}
		if len(ids) > 0 {
			m.replaces[ref] = ids
		}
	}
	for range d.count(1 << 20) {
		ref := decodeRef(&d)
		w := &waiting{Ref: ref}
		d.fixed(w.Record[:])
		w.Type = d.str()
		m.done[ref] = w
		var ids []RecordID
		for range d.count(4096) {
			var id RecordID
			d.fixed(id[:])
			ids = append(ids, id)
		}
		if len(ids) > 0 {
			m.replaces[ref] = ids
		}
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// pruneDone empties the list of applied changes that set a name, with
// the old holders their yeses named (decided by the owner 2026-11-14,
// finding 57). It runs on the state of every snapshot a device builds on,
// which every current device has named, so the list holds only the
// changes since the last such snapshot and never grows without end. A yes
// that arrives later for a pruned change deletes nothing more; if its
// holders still hold the name, the clash shows as "waiting: name taken"
// on every device (SS 8.1). Every device builds on the same snapshots and
// prunes the same list, so all of them end with the same data.
func (m *mergeState) pruneDone() {
	for ref := range m.done {
		delete(m.replaces, ref)
	}
	clear(m.done)
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
	for ref, ids := range m.replaces {
		c.replaces[ref] = slices.Clone(ids)
	}
	for ref, w := range m.done {
		cw := *w
		c.done[ref] = &cw
	}
	maps.Copy(c.markers, m.markers)
	return c
}
