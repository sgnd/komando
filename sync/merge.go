package komandosync

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
)

// The record types the prototype knows. "note" applies by itself; every
// other type holds fields that can move a secret, change what runs or who
// is reached. A deny rule is its own record: a new one applies by itself,
// an edit or a delete of one waits (SS 8.1).
const (
	TypeServer = "server"
	TypeSecret = "secret"
	TypeRule   = "rule"
	TypeDeny   = "deny"
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
	records   map[RecordID]*record
	waiting   map[WriteRef]*waiting
	approved  map[approval]bool   // each verified yes: the write and the record it names
	withdrawn map[withdrawal]bool // waiting changes a yes set aside, by the type of its record
	markers   map[RecordID]WriteRef
}

// approval is one yes as the merge keeps it: a change applies only when a
// yes names its write and its record.
type approval struct {
	Ref    WriteRef
	Record RecordID
}

// withdrawal is a waiting change for a name that a yes for another record
// of Type set aside: it is no longer asked about, unless a yes of its own
// approves it (SS 8.1, finding 69).
type withdrawal struct {
	Ref  WriteRef
	Type string
}

func newMergeState() *mergeState {
	return &mergeState{
		records:   map[RecordID]*record{},
		waiting:   map[WriteRef]*waiting{},
		approved:  map[approval]bool{},
		withdrawn: map[withdrawal]bool{},
		markers:   map[RecordID]WriteRef{},
	}
}

// stricterValues is the table of SS 8.1 (decided by the owner
// 2026-11-14): each rule field has one value that applies by itself; its
// other values wait. It is fixed with the format. A new deny rule, the
// table's last line, is a record type (TypeDeny), not a field.
var stricterValues = map[string]string{
	"protected": "true",     // protected: on
	"approval":  "required", // approval: required
	"never_ai":  "true",     // "Never use AI here": on
}

// stricter reports whether f sets a rule field to its one stricter value.
// It is judged from the new value alone, so the result never depends on
// the order writes arrive in.
func stricter(typ string, f Field) bool {
	v, ok := stricterValues[f.Name]
	return ok && v == f.Value && typ != TypeNote && typ != TypeDevice
}

// appliesItself is SS 8.1's "applies by itself" list for one field of an
// edit: notes and descriptions, and a stricter value from the table.
// Anything else waits.
func appliesItself(typ string, f Field) bool {
	return typ == TypeNote || f.Name == "note" || f.Name == "description" || stricter(typ, f)
}

// wholeAppliesItself reports whether a whole change applies by itself: a
// note, a device's own record, or a new deny rule (never its edit or
// delete).
func wholeAppliesItself(typ string, c *Change) bool {
	return typ == TypeNote || typ == TypeDevice || (typ == TypeDeny && c.Create && !c.Delete)
}

// apply takes in one record change that recordFits accepted, so its type
// is the one fixed in the record ID. Merging is commutative: the same set
// of writes and approvals gives the same state in any order.
func (m *mergeState) apply(ref WriteRef, c *Change, clock HLC) {
	rec := m.records[c.Record]
	if rec == nil {
		rec = &record{Fields: map[string]fieldVal{}}
		m.records[c.Record] = rec
	}
	if rec.Type == "" { // a placeholder an approval's "replaces" made
		rec.Type = c.Type
	}
	if c.Target != (WriteRef{}) {
		// A deny rule written again: several devices may write it, with
		// the same fields. Their own clocks must not count, or the last
		// of them would undo an edit made with a yes in between.
		clock = HLC{}
	}
	w := &waiting{Ref: ref, Record: c.Record, Type: rec.Type, Create: c.Create, Delete: c.Delete, Clock: clock}
	// Notes apply by themselves; a device's name record is written only by
	// that device (recordFits) and pinned by the hash in the signed list
	// entry a person already agreed to; a new deny rule only restricts,
	// and its ID is bound to the write that makes it (recordFits).
	auto := wholeAppliesItself(rec.Type, c)
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
	if auto || m.approved[approval{ref, c.Record}] {
		m.applyWaiting(w)
		return
	}
	m.waiting[ref] = w
}

// approve records a verified yes for the change ref makes to record, of
// type typ, and applies the change if it is here. The same yes deletes
// the old holders of the name it lists (replaces: agreed records and
// deletion markers, decided by the owner 2026-11-14) and sets aside the
// waiting changes for that name it lists (withdraws, finding 69). Both
// are read from the yes alone, never from the state the yes arrives in,
// so a yes has the same effect whether its change is waiting, applied,
// not here yet or inside a snapshot (finding 67), and the result never
// depends on arrival order. A yes deletes only old holders of its own
// record's type: never a device's own record, which no write deletes,
// nor a record of another type a modified client named (SS 8.1).
func (m *mergeState) approve(ref WriteRef, record RecordID, typ string, replaces []RecordID, withdraws []WriteRef) {
	m.approved[approval{ref, record}] = true
	if namesHeld(typ) {
		for _, id := range replaces {
			if id != record && hasType(id, typ) {
				m.markDeleted(id, ref)
			}
		}
		for _, r := range withdraws {
			if r != ref {
				m.withdrawn[withdrawal{r, typ}] = true
			}
		}
	}
	if w := m.waiting[ref]; w != nil && w.Record == record {
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
		m.markDeleted(w.Record, w.Ref)
	}
}

func cmpRecord(a, b RecordID) int { return slices.Compare(a[:], b[:]) }

// markDeleted makes a record's deletion final. The record may not be here
// yet: a placeholder takes its type from its first write.
func (m *mergeState) markDeleted(id RecordID, by WriteRef) {
	rec := m.records[id]
	if rec == nil {
		rec = &record{Fields: map[string]fieldVal{}}
		m.records[id] = rec
	}
	if !rec.Deleted {
		rec.Deleted = true
		m.markers[id] = by
	} else if cur := m.markers[id]; cmpRef(by, cur) < 0 {
		m.markers[id] = by // the same marker whichever order
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
	Ref     WriteRef
	Record  RecordID
	Type    string
	Create  bool
	Delete  bool
	Changes []FieldChange
	// Replaces is a name another record, waiting change or deletion
	// marker holds. Approving the change deletes ReplacesIDs, the agreed
	// records and deletion markers that hold it, in the same signed yes,
	// so two records never hold one name by a yes (SS 8.1). It sets aside
	// Withdraws, the other waiting changes for the name: they are no
	// longer asked about, unless a yes of their own approves them, and
	// then both records stay and show as "waiting: name taken" (finding
	// 69).
	Replaces    string
	ReplacesIDs []RecordID
	Withdraws   []WriteRef
}

// ReplacesLine is the screen's line for a newcomer that takes a held
// name: "replaces prod-db (deleted)". Empty when it takes none.
func (w Waiting) ReplacesLine() string {
	if w.Replaces == "" {
		return ""
	}
	return "replaces " + w.Replaces + " (deleted)"
}

func (m *mergeState) list() []Waiting {
	var out []Waiting
	for _, ref := range slices.SortedFunc(maps.Keys(m.waiting), cmpRef) {
		w := m.waiting[ref]
		rec := m.records[w.Record]
		if rec.Deleted || m.withdrawn[withdrawal{ref, w.Type}] {
			continue // deleted or set aside: there is nothing left to agree to
		}
		v := Waiting{Ref: ref, Record: w.Record, Type: w.Type, Create: w.Create, Delete: w.Delete}
		for _, f := range w.Fields {
			v.Changes = append(v.Changes, FieldChange{Name: f.Name, Old: rec.Fields[f.Name].Value, New: f.Value})
			if f.Name == "name" {
				if ids, refs := m.nameHolders(f.Value, w.Record, w.Type); len(ids)+len(refs) > 0 {
					v.Replaces, v.ReplacesIDs, v.Withdraws = f.Value, ids, refs
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// namesHeld reports whether names of a record type are held (SS 8.1):
// only for types whose new record waits for a person. A note, a device's
// own record and a deny rule apply by themselves, so they can neither
// wait for a name nor hold one.
func namesHeld(typ string) bool {
	return typ != TypeNote && typ != TypeDevice && typ != TypeDeny
}

// hasType reports whether a record ID carries the tag of typ.
func hasType(id RecordID, typ string) bool { return recordID(typ, [12]byte(id[:12])) == id }

// nameHolders lists who else of the same type holds the name (SS 8.1):
// the agreed or deleted records whose name it is, sorted, and the
// waiting changes that set it and are still asked about, sorted. A
// record in the first list is not repeated in the second. Names are held
// per type: a server and a note, or a server and a device, may share
// one.
func (m *mergeState) nameHolders(name string, self RecordID, typ string) ([]RecordID, []WriteRef) {
	if !namesHeld(typ) {
		return nil, nil
	}
	held := map[RecordID]bool{}
	for id, r := range m.records {
		if id != self && r.Fields["name"].Value == name && hasType(id, typ) {
			held[id] = true
		}
	}
	var claims []WriteRef
	for ref, w := range m.waiting {
		if w.Record == self || held[w.Record] || !hasType(w.Record, typ) || m.withdrawn[withdrawal{ref, w.Type}] {
			continue
		}
		if r := m.records[w.Record]; r != nil && r.Deleted {
			continue
		}
		if slices.ContainsFunc(w.Fields, func(f Field) bool { return f.Name == "name" && f.Value == name }) {
			claims = append(claims, ref)
		}
	}
	slices.SortFunc(claims, cmpRef)
	return slices.SortedFunc(maps.Keys(held), cmpRecord), claims
}

// NameClash is a name that two or more agreed, live records of one type
// hold. Two devices offline at once can each take a free name, and
// neither yes replaces anything, because neither saw the other record.
// Decided by the owner 2026-11-14 (SS 8.1): every record in a clash is
// shown as "waiting: name taken" and no command picks any of them by that
// name until a person picks one (KeepName), renames one or deletes one.
// Nothing disappears by itself. A clash is read from the merged records
// alone, so every device that holds the same writes shows the same clash.
type NameClash struct {
	Type    string
	Name    string
	Records []RecordID // sorted
}

// Line is the screen's line for a clash: "waiting: name taken: prod-db
// (2 server records)".
func (c NameClash) Line() string {
	return fmt.Sprintf("waiting: name taken: %s (%d %s records)", c.Name, len(c.Records), c.Type)
}

// clashes lists every name held by two or more agreed, live records of
// one type, sorted by type, then name.
func (m *mergeState) clashes() []NameClash {
	type key struct{ typ, name string }
	held := map[key][]RecordID{}
	for id, r := range m.records {
		n, ok := r.Fields["name"]
		if !r.Exists || r.Deleted || !ok || n.Value == "" || !namesHeld(r.Type) {
			continue
		}
		k := key{r.Type, n.Value}
		held[k] = append(held[k], id)
	}
	var out []NameClash
	for k, ids := range held {
		if len(ids) > 1 {
			slices.SortFunc(ids, cmpRecord)
			out = append(out, NameClash{Type: k.typ, Name: k.name, Records: ids})
		}
	}
	slices.SortFunc(out, func(a, b NameClash) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Name, b.Name))
	})
	return out
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
