package syncproto

import (
	"maps"
	"slices"
)

// The record types the prototype knows. "note" applies by itself; every
// other type holds fields that can move a secret, change what runs or who
// is reached.
const (
	TypeServer = "server"
	TypeSecret = "secret"
	TypeRule   = "rule"
	TypeNote   = "note"
	TypeDevice = "device"
)

type fieldVal struct {
	Value string
	Clock HLC
}

type record struct {
	Type    string
	Fields  map[string]fieldVal
	Exists  bool // its creation is agreed
	Deleted bool
}

// waiting is the part of a change that waits for a person's signed yes.
type waiting struct {
	Ref    WriteRef
	Record RecordID
	Type   string
	Create bool
	Delete bool
	Fields []Field
	Clock  HLC
}

// mergeState is the agreed data on one device: field by field, newest
// clock wins, deletion is final, and a waiting change applies only once
// approved (SS 8.1, 9).
type mergeState struct {
	records  map[RecordID]*record
	waiting  map[WriteRef]*waiting
	approved map[WriteRef]bool
	markers  map[RecordID]WriteRef
}

func newMergeState() *mergeState {
	return &mergeState{
		records:  map[RecordID]*record{},
		waiting:  map[WriteRef]*waiting{},
		approved: map[WriteRef]bool{},
		markers:  map[RecordID]WriteRef{},
	}
}

// appliesItself is SS 8.1's short list: notes and descriptions, and a
// stricter rule. Stricter is decided from the new value alone, so the
// result never depends on the order writes arrive in.
func appliesItself(typ string, f Field) bool {
	if typ == TypeNote {
		return true
	}
	switch f.Name {
	case "note", "description":
		return true
	case "protected":
		return f.Value == "true"
	case "approval":
		return f.Value == "required"
	}
	return false
}

// apply takes in one record change that recordFits accepted, so its type
// is the one fixed in the record ID. Merging is commutative: the same set
// of writes and approvals gives the same state in any order.
func (m *mergeState) apply(ref WriteRef, c *Change, clock HLC) {
	rec := m.records[c.Record]
	if rec == nil {
		rec = &record{Type: c.Type, Fields: map[string]fieldVal{}}
		m.records[c.Record] = rec
	}
	w := &waiting{Ref: ref, Record: c.Record, Type: rec.Type, Create: c.Create, Delete: c.Delete, Clock: clock}
	// Notes apply by themselves; a device's name record is written only by
	// that device (recordFits) and pinned by the hash in the signed list
	// entry a person already agreed to.
	auto := rec.Type == TypeNote || rec.Type == TypeDevice
	if auto {
		w.Fields = c.Fields
	} else {
		for _, f := range c.Fields {
			if !c.Create && appliesItself(rec.Type, f) {
				setField(rec, f, clock)
			} else {
				w.Fields = append(w.Fields, f)
			}
		}
	}
	if !w.Create && !w.Delete && len(w.Fields) == 0 {
		return
	}
	if auto || m.approved[ref] {
		m.applyWaiting(w)
		return
	}
	m.waiting[ref] = w
}

// approve records a verified yes and applies the change if it is here.
func (m *mergeState) approve(ref WriteRef) {
	m.approved[ref] = true
	if w := m.waiting[ref]; w != nil {
		delete(m.waiting, ref)
		m.applyWaiting(w)
	}
}

func (m *mergeState) applyWaiting(w *waiting) {
	rec := m.records[w.Record]
	if w.Create {
		rec.Exists = true
	}
	for _, f := range w.Fields {
		setField(rec, f, w.Clock)
	}
	if w.Delete {
		rec.Deleted = true
		m.markers[w.Record] = w.Ref
	}
}

func setField(rec *record, f Field, clock HLC) {
	if cur, ok := rec.Fields[f.Name]; !ok || cur.Clock.Less(clock) {
		rec.Fields[f.Name] = fieldVal{Value: f.Value, Clock: clock}
	}
}

// Get returns a record's agreed fields; false when it does not exist, is
// deleted, or its creation still waits.
func (m *mergeState) get(id RecordID) (map[string]string, bool) {
	rec := m.records[id]
	if rec == nil || !rec.Exists || rec.Deleted {
		return nil, false
	}
	out := map[string]string{}
	for k, v := range rec.Fields {
		out[k] = v.Value
	}
	return out, true
}

// count is the number of agreed, live records.
func (m *mergeState) count() int {
	n := 0
	for _, r := range m.records {
		if r.Exists && !r.Deleted {
			n++
		}
	}
	return n
}

// FieldChange is one line of the approval screen: "address 10.0.0.5 ->
// 203.0.113.9".
type FieldChange struct {
	Name, Old, New string
}

// Waiting is a change that waits for a person's yes, as the screen shows
// it.
type Waiting struct {
	Ref      WriteRef
	Record   RecordID
	Type     string
	Create   bool
	Delete   bool
	Changes  []FieldChange
	Replaces string // a name another record, waiting change or deletion marker holds
}

func (m *mergeState) list() []Waiting {
	var out []Waiting
	for _, ref := range slices.SortedFunc(maps.Keys(m.waiting), cmpRef) {
		w := m.waiting[ref]
		rec := m.records[w.Record]
		v := Waiting{Ref: ref, Record: w.Record, Type: w.Type, Create: w.Create, Delete: w.Delete}
		for _, f := range w.Fields {
			v.Changes = append(v.Changes, FieldChange{Name: f.Name, Old: rec.Fields[f.Name].Value, New: f.Value})
			if f.Name == "name" && m.nameHeld(f.Value, w.Record) {
				v.Replaces = f.Value
			}
		}
		out = append(out, v)
	}
	return out
}

// nameHeld reports whether another record holds the name: agreed, waiting
// or deleted (SS 8.1).
func (m *mergeState) nameHeld(name string, self RecordID) bool {
	for id, r := range m.records {
		if id != self && r.Fields["name"].Value == name {
			return true
		}
	}
	for _, w := range m.waiting {
		if w.Record == self {
			continue
		}
		for _, f := range w.Fields {
			if f.Name == "name" && f.Value == name {
				return true
			}
		}
	}
	return false
}

func cmpRef(a, b WriteRef) int {
	if c := slices.Compare(a.Writer[:], b.Writer[:]); c != 0 {
		return c
	}
	switch {
	case a.Seq < b.Seq:
		return -1
	case a.Seq > b.Seq:
		return 1
	}
	return 0
}
