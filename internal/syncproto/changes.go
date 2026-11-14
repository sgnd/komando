package syncproto

import "crypto/rand"

// Create adds a record. Unless it is a note it waits for a person's yes,
// because a new server or conn changes who is reached (SS 8.1).
func (d *Device) Create(typ string, fields ...Field) (RecordID, error) {
	var id RecordID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	return d.create(typ, id, fields)
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

func (d *Device) typeOf(id RecordID) string {
	if r := d.data.records[id]; r != nil {
		return r.Type
	}
	return ""
}

// change writes a record change and, on a device with an authority key,
// the person's yes with it.
func (d *Device) change(c *Change) (WriteRef, error) {
	w, err := d.write(c)
	if err != nil {
		return WriteRef{}, err
	}
	ref := w.Ref()
	if _, waits := d.data.waiting[ref]; waits && d.AutoApprove && d.keys.Authority != nil {
		return ref, d.Approve(ref)
	}
	return ref, nil
}

// Approve signs "a person agreed" to a waiting change with the authority
// key (Face ID or Touch ID every time) and writes it.
func (d *Device) Approve(ref WriteRef) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	sig, err := sign(d.keys.Authority, labelApproval, approvalBytes(d.account, ref))
	if err != nil {
		return err
	}
	_, err = d.write(&Change{Kind: kindApproval, Target: ref, Approval: sig})
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

// applyChange merges an opened change. An approval counts only when the
// writer's authority key valid at the write's list entry signed it.
func (d *Device) applyChange(w *Write, c *Change, rep *Report) {
	if c.Kind == kindRecord {
		d.data.apply(w.Ref(), c, w.Clock)
		return
	}
	pub := parsePub(d.list.authKeyAt(w.Writer, w.ListNum))
	if pub == nil || !verifySig(pub, labelApproval, approvalBytes(d.account, c.Target), c.Approval) {
		rep.Rejected++
		return
	}
	d.data.approve(c.Target)
}
