package komandosync

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"maps"
	"slices"
)

// Snapshots (SS 9, decided by the owner 2026-11-14). Without them every
// device checks every write of every device from write 1, and the history
// grows without end. A snapshot is the merged state at one summary:
//
//   - It is signed by one device's sync key.
//   - Every other device accepts it only when it matches its own merged
//     state at the writes the snapshot names; otherwise it refuses it and
//     keeps the writes. A device's summaries name the newest snapshot it
//     accepted.
//   - Writes older than the snapshot go only once every current device has
//     signed a summary naming it (SnapshotToPrune). Each device then builds
//     on the snapshot instead of those writes.
//   - A new device starts from that snapshot, then the writes after it,
//     when the summaries naming it come after every removal.
//   - While a removal of a device waits, and in a snapshot from before a
//     device's removal, nothing of that device past the write the removal
//     records is held (snapCap): those writes are judged by the removal.
//
// It is the one place where old records are sealed again under the newest
// key (SS 7.1): the state is sealed under the vault key of the generation
// in force at the list entry it names, which is the newest its signer had.
// Deletion markers go with it: a deleted record keeps only its type and
// its name, so the deletion stays final and the name stays held.

// Snapshot is a signed copy of the merged state at a set of writes.
type Snapshot struct {
	Account  Hash
	Signer   DeviceID
	Num      uint64 // per signer, counts up
	ListNum  uint32
	ListHash Hash
	KeyGen   uint32 // the generation in force at ListNum
	Heads    []Head // the writes the state holds, sorted by device
	State    Hash   // the hash of the state's one byte form
	Body     sealed // that state, sealed under the vault key of KeyGen, bound to the header
	Sig      Sig
}

func (s *Snapshot) header() []byte {
	var e enc
	e.u8(formatVersion)
	e.u16(suite1)
	e.raw(s.Account[:])
	e.raw(s.Signer[:])
	e.u64(s.Num)
	e.u32(s.ListNum)
	e.raw(s.ListHash[:])
	e.u32(s.KeyGen)
	e.u32(uint32(len(s.Heads)))
	for _, h := range s.Heads {
		e.raw(h.Device[:])
		e.u64(h.Seq)
		e.raw(h.Hash[:])
	}
	e.raw(s.State[:])
	return e.b
}

func (s *Snapshot) signedBytes() []byte { return append(s.header(), s.Body.bytes()...) }

// Hash covers the signed content, never the signature.
func (s *Snapshot) Hash() Hash { return sum(labelSnapHash, s.signedBytes()) }

// Marshal is the snapshot as stored.
func (s *Snapshot) Marshal() []byte { return append(s.signedBytes(), s.Sig[:]...) }

// ParseSnapshot reads a stored snapshot.
func ParseSnapshot(b []byte) (*Snapshot, error) {
	d := dec{b: b}
	if d.u8() != formatVersion || d.u16() != suite1 {
		return nil, ErrBadSnapshot
	}
	s := &Snapshot{}
	d.fixed(s.Account[:])
	d.fixed(s.Signer[:])
	s.Num = d.u64()
	s.ListNum = d.u32()
	d.fixed(s.ListHash[:])
	s.KeyGen = d.u32()
	for range d.count(4096) {
		var h Head
		d.fixed(h.Device[:])
		h.Seq = d.u64()
		d.fixed(h.Hash[:])
		s.Heads = append(s.Heads, h)
	}
	d.fixed(s.State[:])
	s.Body = decodeSealed(&d)
	d.fixed(s.Sig[:])
	if err := d.done(); err != nil {
		return nil, ErrBadSnapshot
	}
	for i := 1; i < len(s.Heads); i++ {
		if bytes.Compare(s.Heads[i-1].Device[:], s.Heads[i].Device[:]) >= 0 {
			return nil, ErrBadSnapshot
		}
	}
	return s, nil
}

func (s *Snapshot) headMap() map[DeviceID]Head {
	m := make(map[DeviceID]Head, len(s.Heads))
	for _, h := range s.Heads {
		m[h.Device] = h
	}
	return m
}

func logSnapshots(id DeviceID) string { return "p/" + hexID(id) }

// MakeSnapshot signs the state this device holds after a sync and stores
// it. The device accepts its own snapshot; its next summary names it.
func (d *Device) MakeSnapshot() (*Snapshot, error) {
	if d.kitToType != nil {
		return nil, ErrKitNotConfirmed
	}
	if d.summaries[d.id] == nil || len(d.deferred) > 0 {
		return nil, fmt.Errorf("%w: sync first, with no writes waiting for their time", ErrWaiting)
	}
	gen := d.list.GenAt[d.head-1]
	vk := d.vaultKeys[gen]
	if vk == nil {
		return nil, ErrNoKey
	}
	s := &Snapshot{
		Account: d.account, Signer: d.id, Num: d.snapNum + 1,
		ListNum: d.head, ListHash: d.headHash, KeyGen: gen,
	}
	state := d.data
	for _, id := range slices.SortedFunc(maps.Keys(d.applied), cmpDevice) {
		h := d.applied[id]
		if c, ok := d.snapCap(id, s.ListNum); ok && h.Seq > c {
			// A removal of this device waits: the snapshot stops at the
			// write it records (SS 6.2, 9).
			h, state = Head{Device: id, Seq: c, Hash: d.hashAt(id, c, nil)}, nil
		}
		s.Heads = append(s.Heads, h)
	}
	heads := s.headMap()
	if state == nil {
		state = d.stateAt(heads)
	}
	plain := state.encode(heads)
	s.State = sum(labelSnapState, plain)
	body, err := sealRecord(vk, s.header(), plain)
	if err != nil {
		return nil, err
	}
	s.Body = body
	if s.Sig, err = sign(d.keys.Sync, labelSnapshot, s.signedBytes()); err != nil {
		return nil, err
	}
	if err := d.srv.Append(d.id, logSnapshots(d.id), s.Marshal()); err != nil {
		return nil, err
	}
	d.snapNum, d.snap = s.Num, s
	return s, nil
}

// checkSnapshot checks a snapshot's signature and place: signed by the
// sync key of a device ever on the list, for this account, naming a list
// entry this device holds, sealed under the generation in force there.
func (d *Device) checkSnapshot(s *Snapshot) error {
	rec, ok := d.list.Ever[s.Signer]
	if !ok || s.Account != d.account || !verifySig(parsePub(rec.SyncPub), labelSnapshot, s.signedBytes(), s.Sig) {
		return ErrBadSignature
	}
	if s.ListNum == 0 || s.ListNum > d.head || d.list.Hashes[s.ListNum-1] != s.ListHash {
		return fmt.Errorf("%w: a snapshot names list entry %d", ErrBadSnapshot, s.ListNum)
	}
	if s.KeyGen != d.list.GenAt[s.ListNum-1] {
		return fmt.Errorf("%w: sealed under key generation %d, entry %d has %d", ErrBadSnapshot, s.KeyGen, s.ListNum, d.list.GenAt[s.ListNum-1])
	}
	return nil
}

// snapshotLog reads the snapshots of one device, newest first. Ones that
// do not parse are left out: the server can always withhold, and a
// snapshot is only ever taken after it is checked.
func (d *Device) snapshotLog(id DeviceID) ([]*Snapshot, error) {
	items, err := d.srv.Read(d.id, logSnapshots(id))
	if err != nil {
		return nil, err
	}
	var out []*Snapshot
	for _, it := range items {
		if s, err := ParseSnapshot(it); err == nil && s.Signer == id {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *Snapshot) int {
		switch {
		case a.Num > b.Num:
			return -1
		case a.Num < b.Num:
			return 1
		}
		return 0
	})
	return out, nil
}

// The answers of judging a snapshot against this device's own data.
const (
	snapNotYet   = iota // this device does not hold all its writes yet, or holds a newer base
	snapMatches         // its state is this device's state at its writes
	snapMismatch        // it differs: refused, the writes are kept
	snapUnfit           // it holds writes of a removed device past its floor: never taken
)

// snapCap is the newest write of dev that a snapshot naming list entry
// listNum may hold (SS 6.2, 9). While a removal of dev waits, and for a
// snapshot from before dev's removal, that is the write the removal
// records (or the snapshot this device builds on, if later: finding 43).
// Writes past it are judged by the removal rules, which a state made
// before the removal applied did not follow; once in a base, no rule
// could take them apart. ok is false when there is no cap.
func (d *Device) snapCap(dev DeviceID, listNum uint32) (uint64, bool) {
	c, ok := uint64(0), false
	low := func(seq uint64) {
		seq = max(seq, d.baseHeads[dev].Seq)
		if !ok || seq < c {
			c, ok = seq, true
		}
	}
	if r, removed := d.list.Removed[dev]; removed && listNum < d.list.RemInfo[dev].At {
		low(r.LastSeq)
	}
	for _, p := range d.list.Pending {
		if p.Done {
			continue
		}
		for _, r := range p.Inner.Removes {
			if r.Device == dev {
				low(r.LastSeq)
			}
		}
	}
	return c, ok
}

// fits reports whether a snapshot holds no write past a cap.
func (d *Device) fits(s *Snapshot) bool {
	for _, h := range s.Heads {
		if c, ok := d.snapCap(h.Device, s.ListNum); ok && h.Seq > c {
			return false
		}
	}
	return true
}

// judge compares a snapshot with this device's merged state at the writes
// it names.
func (d *Device) judge(s *Snapshot) int {
	if !d.fits(s) {
		return snapUnfit
	}
	heads := s.headMap()
	for id, b := range d.baseHeads {
		if heads[id].Seq < b.Seq {
			return snapNotYet
		}
	}
	for id, h := range heads {
		if d.applied[id].Seq < h.Seq {
			return snapNotYet
		}
		if h.Seq > 0 && d.hashAt(id, h.Seq, nil) != h.Hash {
			return snapMismatch
		}
	}
	for _, w := range d.deferred {
		if w.w.Seq <= heads[w.w.Writer].Seq {
			return snapNotYet
		}
	}
	m := d.stateAt(heads)
	got := sum(labelSnapState, m.encode(heads))
	if subtle.ConstantTimeCompare(got[:], s.State[:]) != 1 {
		return snapMismatch
	}
	return snapMatches
}

// stateAt merges again, from the base, only the writes up to heads.
func (d *Device) stateAt(heads map[DeviceID]Head) *mergeState {
	m := d.baseData()
	var rep Report
	for _, s := range d.log {
		if s.w.Seq <= heads[s.w.Writer].Seq {
			d.applyTo(m, s.w, s.c, &rep)
		}
	}
	return m
}

// covers reports whether every write a names is at or before the one b
// names.
func covers(b, a *Snapshot) bool {
	hb := b.headMap()
	for _, h := range a.Heads {
		if hb[h.Device].Seq < h.Seq {
			return false
		}
	}
	return true
}

// checkSnapshots runs in each sync. The snapshot this device accepted is
// judged again until it builds on it, so a removal that changes what the
// writes give takes it back. A newer snapshot of a listed device that
// covers it is judged and, when it matches, accepted. One that differs is
// refused and shown; the writes stay.
func (d *Device) checkSnapshots(rep *Report) error {
	if d.snap != nil && d.snap.Hash() != d.baseHash {
		if j := d.judge(d.snap); j == snapMismatch || j == snapUnfit {
			d.refused[d.snap.Hash()] = true
			d.snap = nil
		}
	}
	for _, id := range slices.SortedFunc(maps.Keys(d.list.Members), cmpDevice) {
		log, err := d.snapshotLog(id)
		if err != nil {
			return err
		}
		if len(log) == 0 {
			continue
		}
		s := log[0] // only the newest of each device is judged
		h := s.Hash()
		if d.refused[h] || (d.snap != nil && (h == d.snap.Hash() || !covers(s, d.snap))) {
			continue
		}
		if err := d.checkSnapshot(s); err != nil {
			return err
		}
		switch d.judge(s) {
		case snapMatches:
			d.snap = s
		case snapMismatch:
			d.refused[h] = true
			rep.Refused++
		case snapUnfit:
			// Made before this device saw a removal, or by a device that
			// ignores the caps: not an error to alert on, never taken.
			d.refused[h] = true
		}
	}
	return nil
}

// confirmedSnapshot is the snapshot every current device named in its
// newest summary, as this device holds them; nil when there is none.
func (d *Device) confirmedSnapshot(sums map[DeviceID]*Summary) Hash {
	var h Hash
	for id := range d.list.Members {
		s := sums[id]
		if s == nil || s.Snap == (Hash{}) || (h != Hash{} && s.Snap != h) {
			return Hash{}
		}
		h = s.Snap
	}
	return h
}

// rebase builds on the accepted snapshot once every current device named
// it: its state becomes the base and the writes it holds leave this
// device's log, so the server may drop them too (SS 9).
func (d *Device) rebase() {
	if d.snap == nil || d.snap.Hash() == d.baseHash || d.confirmedSnapshot(d.summaries) != d.snap.Hash() {
		return
	}
	heads := d.snap.headMap()
	base, err := decodeState(d.stateAt(heads).encode(heads))
	if err != nil {
		return // cannot happen: encode and decode are one form
	}
	d.installBase(d.snap, base)
}

// installBase makes s, with state base, what this device builds on.
func (d *Device) installBase(s *Snapshot, base *mergeState) {
	heads := s.headMap()
	var log []staged
	for _, st := range d.log {
		if st.w.Seq > heads[st.w.Writer].Seq {
			log = append(log, st)
		}
	}
	for id, h := range heads {
		old := d.baseHeads[id].Seq
		if hs := d.hashes[id]; h.Seq >= old && h.Seq-old <= uint64(len(hs)) {
			d.hashes[id] = slices.Clone(hs[h.Seq-old:])
		} else {
			d.hashes[id] = nil
		}
		if d.applied[id].Seq < h.Seq {
			d.applied[id] = h
		}
	}
	d.base, d.baseHeads, d.baseHash, d.baseSnap, d.snap = base, heads, s.Hash(), s, s
	d.log = nil
	d.data = d.baseData()
	var rep Report
	for _, st := range log {
		d.applyChange(st.w, st.c, &rep)
		d.log = append(d.log, st)
	}
}

// startFromSnapshot is a new device's first sync (SS 9). It takes the
// newest snapshot that every other current device named in its newest
// signed summary, or else the one they all build on, checks its state
// against the hash its signer signed, and then reads only the writes
// after it. When they agree on none, it reads every write from write 1.
func (d *Device) startFromSnapshot() error {
	for id, h := range d.applied {
		if id != d.id && h.Seq > 0 {
			return nil
		}
	}
	if d.base != nil || d.summaries[d.id] != nil {
		return nil
	}
	var tops []*Summary
	for id, m := range d.list.Members {
		if id == d.id {
			continue
		}
		log, err := d.summaryLog(id)
		if err != nil {
			return err
		}
		var top *Summary
		for _, s := range log {
			if top == nil || s.Num > top.Num {
				top = s
			}
		}
		if top == nil {
			return nil
		}
		if top.Account != d.account || top.Signer != id || !verifySig(parsePub(m.Rec.SyncPub), labelSummary, top.signedBytes(), top.Sig) {
			return fmt.Errorf("%w: summary of %x", ErrBadSignature, id[:4])
		}
		if top.ListNum < d.lastRemovalEntry() {
			// A summary from before a removal, or before a removal was
			// asked for, judged the snapshot it names without that
			// removal: the others may take it back. Read from write 1.
			return nil
		}
		tops = append(tops, top)
	}
	want := common(tops, func(s *Summary) Hash { return s.Snap })
	if want == (Hash{}) {
		want = common(tops, func(s *Summary) Hash { return s.Base })
	}
	if want == (Hash{}) {
		return nil
	}
	for _, id := range slices.SortedFunc(maps.Keys(d.list.Ever), cmpDevice) {
		log, err := d.snapshotLog(id)
		if err != nil {
			return err
		}
		for _, s := range log {
			if s.Hash() != want {
				continue
			}
			if err := d.checkSnapshot(s); err != nil {
				return err
			}
			if !d.fits(s) {
				return nil // read from write 1
			}
			vk := d.vaultKeys[s.KeyGen]
			if vk == nil {
				return ErrNoKey
			}
			plain, err := openRecord(vk, s.header(), s.Body)
			if err != nil {
				return err
			}
			got := sum(labelSnapState, plain)
			if subtle.ConstantTimeCompare(got[:], s.State[:]) != 1 {
				return ErrBadSnapshot
			}
			base, err := decodeState(plain)
			if err != nil {
				return ErrBadSnapshot
			}
			d.installBase(s, base)
			return d.computeCuts() // a floor is never below the snapshot
		}
	}
	return fmt.Errorf("%w: the snapshot every device names is not on the server", ErrMissingWrites)
}

// lastRemovalEntry is the newest list entry that removes a device, asks
// for a removal that waits, or applies or cancels one; 0 when there is
// none.
func (d *Device) lastRemovalEntry() uint32 {
	var n uint32
	for _, en := range d.list.Entries {
		b := &en.Body
		switch {
		case len(b.Removes) > 0, b.Inner != nil && len(b.Inner.Removes) > 0:
			n = en.Num
		case b.Action == ActApply || b.Action == ActCancel:
			if p := d.list.Pending[b.Ref]; p != nil && len(p.Inner.Removes) > 0 {
				n = en.Num
			}
		}
	}
	return n
}

// common is the one value every summary gives, or zero.
func common(sums []*Summary, of func(*Summary) Hash) Hash {
	var h Hash
	for i, s := range sums {
		v := of(s)
		if i > 0 && v != h {
			return Hash{}
		}
		h = v
	}
	return h
}

// SnapshotToPrune is the snapshot this device builds on: every current
// device signed a summary naming it, so the writes it holds may go from
// the server (SS 9). Nil when there is none.
func (d *Device) SnapshotToPrune() *Snapshot { return d.baseSnap }

func cmpDevice(a, b DeviceID) int { return bytes.Compare(a[:], b[:]) }

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
