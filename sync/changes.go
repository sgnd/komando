package komandosync

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// Create adds a record. Unless it is a note it waits for a person's yes,
// because a new server or conn changes who is reached (SS 8.1).
func (d *Device) Create(typ string, fields ...Field) (RecordID, error) {
	if typ == TypeDeny {
		return d.create(typ, denyID(d.id, d.ownSeq+1), fields)
	}
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return RecordID{}, err
	}
	return d.create(typ, recordID(typ, rnd), fields)
}

// recordID is 12 random bytes and a 4-byte tag of the record type. The
// type is fixed when the ID is made: a write that names another type for
// the ID is refused, so no writer can turn a server into a note and skip
// the person's yes, and merging never depends on which write came first.
func recordID(typ string, rnd [12]byte) RecordID {
	var id RecordID
	copy(id[:12], rnd[:])
	h := sum(labelRecordType, []byte(typ), rnd[:])
	copy(id[12:], h[:4])
	return id
}

// recordFits reports whether write seq of writer may make change c: the
// type matches the one fixed in the record ID; a device record is written
// only by that device and never deleted (it ends with the device's
// removal); and a deny rule is made only by the write its ID names, so a
// later "create" can never pass off an edit of it as a new rule.
func recordFits(writer DeviceID, seq uint64, c *Change) bool {
	want := recordID(c.Type, [12]byte(c.Record[:12]))
	if c.Type == "" || subtle.ConstantTimeCompare(want[:], c.Record[:]) != 1 {
		return false
	}
	if c.Target != (WriteRef{}) {
		// Only a deny rule written again names a write (removal.go).
		return c.Type == TypeDeny && c.Create && !c.Delete && c.Record == denyAgainID(c.Target, c.Fields)
	}
	switch c.Type {
	case TypeDevice:
		return c.Record == idRecord(writer) && !c.Delete
	case TypeDeny:
		return !c.Create || c.Record == denyID(writer, seq)
	}
	return true
}

// denyAgainID is the ID of a removed device's deny rule written again
// from past its cut (SS 6.2). It is bound to the dropped write and to the
// rule's fields, so every device that writes it again writes the same
// record with the same fields, and one rule results, not one per device.
func denyAgainID(t WriteRef, fields []Field) RecordID {
	var e enc
	e.raw(t.Writer[:])
	e.u64(t.Seq)
	e.raw(t.Hash[:])
	e.u32(uint32(len(fields)))
	for _, f := range fields {
		e.str(f.Name)
		e.str(f.Value)
	}
	h := sum(labelDenyAgain, e.b)
	return recordID(TypeDeny, [12]byte(h[:12]))
}

// denyID is the ID of the deny rule that write seq of writer makes.
func denyID(writer DeviceID, seq uint64) RecordID {
	h := sum(labelDenyID, writer[:], binary.BigEndian.AppendUint64(nil, seq))
	return recordID(TypeDeny, [12]byte(h[:12]))
}

func (d *Device) create(typ string, id RecordID, fields []Field) (RecordID, error) {
	_, err := d.change(&Change{Kind: kindRecord, Record: id, Type: typ, Create: true, Fields: fields})
	return id, err
}

// Update changes fields of a record, field by field.
func (d *Device) Update(id RecordID, fields ...Field) (WriteRef, error) {
	return d.change(&Change{Kind: kindRecord, Record: id, Type: d.typeOf(id), Fields: fields})
}

// Delete leaves a signed deletion marker. It waits like any change not on
// the "applies by itself" list (SS 8.1), except for notes.
func (d *Device) Delete(id RecordID) (WriteRef, error) {
	return d.change(&Change{Kind: kindRecord, Record: id, Type: d.typeOf(id), Delete: true})
}

// KeepName is the person's pick in a name clash: keep this record under
// the name. It writes the record's name again, so the change waits with
// the line "replaces prod-db (deleted)" for the other holders, and the
// person's yes on that screen deletes them (SS 8.1). That yes is never
// implied by editing. To keep both, the person renames one instead
// (Update with a new name), which waits like any rename.
func (d *Device) KeepName(id RecordID) (WriteRef, error) {
	r := d.data.records[id]
	if r == nil || !r.Exists || r.Deleted {
		return WriteRef{}, ErrNoRecord
	}
	name := r.Fields["name"].Value
	if !slices.ContainsFunc(d.data.clashes(), func(c NameClash) bool { return c.Type == r.Type && c.Name == name }) {
		return WriteRef{}, fmt.Errorf("%w: %q is held by this record only", ErrBadWrite, name)
	}
	return d.Update(id, Field{Name: "name", Value: name})
}

func (d *Device) typeOf(id RecordID) string {
	if r := d.data.records[id]; r != nil {
		return r.Type
	}
	return ""
}

// change writes a record change and, on a device with an authority key,
// the person's yes with it.
func (d *Device) change(c *Change) (WriteRef, error) {
	if !recordFits(d.id, d.ownSeq+1, c) {
		return WriteRef{}, ErrBadWrite
	}
	if c.Type == TypeSecret {
		if err := d.refreshBeforeSecret(); err != nil {
			return WriteRef{}, err
		}
	}
	w, err := d.write(c)
	if err != nil {
		return WriteRef{}, err
	}
	ref := w.Ref()
	if _, waits := d.data.waiting[ref]; waits && d.AutoApprove && d.keys.Authority != nil && len(d.replacesOf(ref)) == 0 {
		return ref, d.Approve(ref)
	}
	return ref, nil
}

// replacesOf is the old holders of the name a waiting change takes. A yes
// that deletes them is never implied by editing: the change waits until
// the person has seen "replaces prod-db (deleted)" (SS 8.1).
func (d *Device) replacesOf(ref WriteRef) []RecordID {
	for _, w := range d.data.list() {
		if w.Ref == ref {
			return w.ReplacesIDs
		}
	}
	return nil
}

// refreshBeforeSecret refreshes the list before a secret is sealed, so a
// removal is seen before the secret goes out under the old key (SS 7.1).
// When the list cannot be read, the person is asked: "could not check for
// removed devices; save anyway?" (ConfirmUnchecked). A list that reads but
// fails a check is never saved past.
func (d *Device) refreshBeforeSecret() error {
	err := d.refreshList()
	if err == nil {
		return d.loadKeys()
	}
	if slices.ContainsFunc(protocolErrors, func(e error) bool { return errors.Is(err, e) }) {
		return err
	}
	if d.ConfirmUnchecked != nil && d.ConfirmUnchecked(err) {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrListUnchecked, err)
}

// Approve signs "a person agreed" to a waiting change with the authority
// key (Face ID or Touch ID every time) and writes it. A change that takes
// a held name is shown as "replaces prod-db (deleted)", and the same yes
// deletes the old holders (SS 8.1).
func (d *Device) Approve(ref WriteRef) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	replaces := d.replacesOf(ref)
	sig, err := sign(d.keys.Authority, labelApproval, approvalBytes(d.account, ref, replaces))
	if err != nil {
		return err
	}
	_, err = d.write(&Change{Kind: kindApproval, Target: ref, Replaces: replaces, Approval: sig})
	return err
}

// write seals, signs and stores one change, and applies it here.
func (d *Device) write(c *Change) (*Write, error) {
	if d.kitToType != nil {
		return nil, ErrKitNotConfirmed
	}
	gen := d.list.Gen.Gen
	vk := d.vaultKeys[gen]
	if vk == nil {
		return nil, ErrNoKey
	}
	w := &Write{
		Account: d.account, Vault: d.vaultID(), Writer: d.id, Seq: d.ownSeq + 1, Prev: d.ownHash,
		ListNum: d.head, ListHash: d.headHash, KeyGen: gen, Clock: d.tick(),
	}
	body, err := sealRecord(vk, w.header(), c.marshal())
	if err != nil {
		return nil, err
	}
	w.Body = body
	if w.Sig, err = sign(d.keys.Sync, labelWrite, w.signedBytes()); err != nil {
		return nil, err
	}
	if err := d.srv.Append(d.id, logWrites(d.id), w.Marshal()); err != nil {
		return nil, err
	}
	h := w.Hash()
	d.ownSeq, d.ownHash = w.Seq, h
	d.applied[d.id] = Head{Device: d.id, Seq: w.Seq, Hash: h}
	d.hashes[d.id] = append(d.hashes[d.id], h)
	var rep Report
	d.applyChange(w, c, &rep)
	d.log = append(d.log, staged{w, c})
	return w, nil
}

// applyChange merges an opened change. A removed device's change past its
// floor keeps only what applies by itself (removal.go). An approval counts
// only when the writer's authority key valid at the write's list entry
// signed it.
func (d *Device) applyChange(w *Write, c *Change, rep *Report) { d.applyTo(d.data, w, c, rep) }

// applyTo is applyChange into m: the live data, or a state rebuilt to
// check a snapshot.
func (d *Device) applyTo(m *mergeState, w *Write, c *Change, rep *Report) {
	if c = d.pastFloor(w, c, rep); c == nil {
		return
	}
	switch c.Kind {
	case kindRecord:
		if !recordFits(w.Writer, w.Seq, c) {
			rep.Rejected++
			return
		}
		m.apply(w.Ref(), c, w.Clock)
		return
	}
	pub := parsePub(d.list.authKeyAt(w.Writer, w.ListNum))
	if pub == nil || !verifySig(pub, labelApproval, approvalBytes(d.account, c.Target, c.Replaces), c.Approval) {
		rep.Rejected++
		return
	}
	m.approve(c.Target, c.Replaces)
}
