package komandosync

import (
	"fmt"
	"slices"
)

// Which writes of a removed device count (SS 6.2, decided by the owner
// 2026-11-14):
//
//   - Up to the floor, the last write the removal records, everything
//     stays as it was.
//   - Past the floor, up to the cut, only writes that apply by themselves
//     are kept: notes, descriptions, stricter values, a new deny rule. Its
//     approvals and waiting changes are dropped on every device and shown
//     to the person, who can give a fresh yes. This rule depends only on
//     the list, so every device does the same, and a summary that moves
//     the cut can never bring in a change that needs a person.
//   - Past the cut, everything is dropped and shown. A device that had
//     already applied a stricter value from there writes it again as its
//     own write, so every device ends with the same value.
//
// The cut is the newest write of the removed device that a device still
// on the list covered in a signed summary naming a list entry from before
// the removal.

// dropNote is a write of a removed device that was not kept, wholly or in
// part, as the person sees it.
type dropNote struct {
	pastCut   bool // dropped whole; false: past the floor, only what applies by itself was kept
	confirmed bool // the person saw it
}

// floorOf is a removed device's floor: the last write its removal records,
// or the newest write of it a confirmed snapshot holds, if later. A
// snapshot every current device confirmed is never taken apart.
func (d *Device) floorOf(id DeviceID) Head {
	r := d.list.Removed[id]
	f := Head{Device: id, Seq: r.LastSeq, Hash: r.LastHash}
	if b, ok := d.baseHeads[id]; ok && b.Seq > f.Seq {
		f = b
	}
	return f
}

// summaryLog reads a device's summary log, sorted by number. Each
// summary names the hash of the one before it, so a signer's summaries
// form one chain (SS 6.2, 9). It refuses:
//
//   - two different summaries with one number, or a summary that does not
//     follow the one before it (ErrFork): a stolen sync key cannot slip
//     in a summary beside an old one;
//   - a log whose named list entry goes down as the number goes up, also
//     against the newest summary of this signer this device holds, which
//     the server may hide (ErrRollback): an honest device never names an
//     older entry than before, so a stolen sync key cannot backdate a
//     summary to before a removal;
//   - a summary with the number of the one this device holds that is not
//     that one (ErrFork).
func (d *Device) summaryLog(id DeviceID) ([]*Summary, error) {
	items, err := d.srv.Read(d.id, logSummaries(id))
	if err != nil {
		return nil, err
	}
	out := make([]*Summary, 0, len(items))
	for _, it := range items {
		s, err := ParseSummary(it)
		if err != nil {
			return nil, fmt.Errorf("%w: summary of %x", ErrBadSignature, id[:4])
		}
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b *Summary) int { return cmpU64(a.Num, b.Num) })
	mine := d.summaries[id]
	for i, s := range out {
		if mine != nil {
			switch {
			case s.Num == mine.Num && s.Hash() != mine.Hash():
				return nil, fmt.Errorf("%w: summary %d of %x is not the one this device holds", ErrFork, s.Num, id[:4])
			case s.Num > mine.Num && s.ListNum < mine.ListNum:
				return nil, fmt.Errorf("%w: summary %d of %x names list entry %d after summary %d named %d",
					ErrRollback, s.Num, id[:4], s.ListNum, mine.Num, mine.ListNum)
			}
		}
		if i == 0 {
			continue
		}
		p := out[i-1]
		switch {
		case s.Num == p.Num:
			if s.Hash() != p.Hash() {
				return nil, fmt.Errorf("%w: two different summaries %d of %x", ErrFork, s.Num, id[:4])
			}
		case s.Num == p.Num+1 && s.Prev != p.Hash():
			return nil, fmt.Errorf("%w: summary %d of %x does not follow summary %d", ErrFork, s.Num, id[:4], p.Num)
		}
		if s.ListNum < p.ListNum {
			return nil, fmt.Errorf("%w: summary %d of %x names list entry %d after summary %d named %d",
				ErrRollback, s.Num, id[:4], s.ListNum, p.Num, p.ListNum)
		}
	}
	return slices.CompactFunc(out, func(a, b *Summary) bool { return a.Num == b.Num }), nil
}

// chainedTo reports whether log holds every summary from s up to the one
// this device holds of that signer, so s is in its chain. A summary the
// server could have slipped in beside an old one, with the ones after it
// hidden, does not count toward a cut.
func (d *Device) chainedTo(log []*Summary, s *Summary) bool {
	mine := d.summaries[s.Signer]
	if mine == nil || s.Num >= mine.Num {
		return true
	}
	next := s.Num
	for _, x := range log {
		if x.Num == next+1 {
			next = x.Num
		}
	}
	return next >= mine.Num
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// computeCuts finds each removed device's cut. Only a summary whose signer
// is still on the list counts. A cut found once stays while the device
// whose summary set it is still listed, so a server that hides that
// summary later cannot lower it; once that device is removed too, the cut
// is found again without it, as a device that never saw it would.
func (d *Device) computeCuts() error {
	for id := range d.list.Removed {
		floor := d.floorOf(id)
		best, by := floor, DeviceID{}
		info := d.list.RemInfo[id]
		for _, other := range info.Remaining {
			m := d.list.Members[other]
			if m == nil {
				continue
			}
			log, err := d.summaryLog(other)
			if err != nil {
				return err
			}
			var top *Summary
			var topHead Head
			for _, s := range log {
				if h := headOf(s, id); s.ListNum < info.At && h.Seq > topHead.Seq && d.chainedTo(log, s) {
					top, topHead = s, h
				}
			}
			if top == nil || topHead.Seq <= best.Seq {
				continue
			}
			if top.Account != d.account || top.Signer != other ||
				!verifySig(parsePub(m.Rec.SyncPub), labelSummary, top.signedBytes(), top.Sig) {
				return fmt.Errorf("%w: summary of %x", ErrBadSignature, other[:4])
			}
			if top.ListNum == 0 || d.list.Hashes[top.ListNum-1] != top.ListHash {
				return fmt.Errorf("%w: a summary names another list entry %d", ErrFork, top.ListNum)
			}
			best, by = topHead, other
		}
		if prev, ok := d.cuts[id]; ok {
			_, listed := d.list.Members[d.cutBy[id]]
			switch {
			case prev.Seq > best.Seq && listed:
				best, by = prev, d.cutBy[id]
			case prev.Seq == best.Seq && prev.Hash != best.Hash:
				return fmt.Errorf("%w: two different writes %d of a removed device", ErrFork, best.Seq)
			}
		}
		d.cuts[id], d.cutBy[id] = best, by
	}
	return nil
}

// dropRevoked merges again when the merged data does not follow the rules
// above yet: a removal is new and this device applied writes past its
// floor, or a cut went below what this device applied. Merging is
// order-free, so the result is what a device that applied only the
// writes that count holds. A stricter value this device applied from past
// the cut is written again as its own write (d.rewrite, written by Sync).
func (d *Device) dropRevoked(rep *Report) error {
	drop := map[DeviceID]uint64{}
	again := false
	for id := range d.list.Removed {
		c := d.cuts[id]
		if d.newest[id].Seq > c.Seq {
			d.newest[id] = c
		}
		if !d.ruled[id] && d.applied[id].Seq > d.floorOf(id).Seq {
			again = true
		}
		d.ruled[id] = true
		if d.applied[id].Seq <= c.Seq {
			continue
		}
		if c.Seq > 0 && d.hashAt(id, c.Seq, nil) != c.Hash {
			return fmt.Errorf("%w: the last write that counts of a removed device differs", ErrFork)
		}
		drop[id] = c.Seq
		d.applied[id] = c
		d.hashes[id] = d.hashes[id][:c.Seq-d.baseHeads[id].Seq]
		again = true
	}
	if !again {
		return nil
	}
	old, held := d.log, d.data
	d.log, d.data = nil, d.baseData()
	var strict []*Change
	for _, s := range old {
		if last, ok := drop[s.w.Writer]; ok && s.w.Seq > last {
			d.countRevoked(s.w.Ref(), rep)
			d.noteDropped(s.w.Ref())
			if c := inForce(held, s.w, s.c, stricterPart(s.w, s.c)); c != nil {
				strict = append(strict, c)
			}
			continue
		}
		d.applyChange(s.w, s.c, rep)
		d.log = append(d.log, s)
	}
	for _, c := range strict {
		if c = d.notYetHere(c); c != nil {
			d.rewrite = append(d.rewrite, c)
		}
	}
	return nil
}

// keptPastFloor is what counts of a removed device's change between its
// floor and its cut: what applies by itself. Nil when nothing does: an
// approval, a waiting change, a new record that is not a note.
func keptPastFloor(c *Change) *Change {
	if c.Kind != kindRecord {
		return nil
	}
	if wholeAppliesItself(c.Type, c) {
		return c
	}
	if c.Create || c.Delete {
		return nil
	}
	var keep []Field
	for _, f := range c.Fields {
		if appliesItself(c.Type, f) {
			keep = append(keep, f)
		}
	}
	switch len(keep) {
	case 0:
		return nil
	case len(c.Fields):
		return c
	}
	return &Change{Kind: kindRecord, Record: c.Record, Type: c.Type, Fields: keep}
}

// stricterPart is the part of write w's change that only tightens:
// stricter rule values, or a new deny rule, which is written again under
// the ID denyAgainID gives. Nil when there is none.
func stricterPart(w *Write, c *Change) *Change {
	if c.Kind != kindRecord || c.Delete {
		return nil
	}
	if c.Type == TypeDeny && c.Create {
		ref := w.Ref()
		return &Change{Kind: kindRecord, Record: denyAgainID(ref, c.Fields), Type: TypeDeny, Create: true, Fields: c.Fields, Target: ref}
	}
	if c.Create {
		return nil
	}
	var keep []Field
	for _, f := range c.Fields {
		if stricter(c.Type, f) {
			keep = append(keep, f)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return &Change{Kind: kindRecord, Record: c.Record, Type: c.Type, Fields: keep}
}

// inForce is the part of c, the stricter part of write w's change orig,
// that was in force in the merged data before merging again (held): the
// field still had the dropped write's value and clock, or the deny rule
// was still there. A value a newer write replaced, a person's yes for
// example, is not written again (SS 6.2: "already applied ... keeps").
func inForce(held *mergeState, w *Write, orig, c *Change) *Change {
	if c == nil {
		return nil
	}
	if c.Type == TypeDeny {
		if r := held.records[orig.Record]; r == nil || !r.Exists || r.Deleted {
			return nil
		}
		return c
	}
	r := held.records[c.Record]
	if r == nil || r.Deleted {
		return nil
	}
	var keep []Field
	for _, f := range c.Fields {
		if r.Fields[f.Name] == (fieldVal{Value: f.Value, Clock: w.Clock}) {
			keep = append(keep, f)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return &Change{Kind: kindRecord, Record: c.Record, Type: c.Type, Fields: keep}
}

// notYetHere is the part of a stricter change the merged data does not
// hold yet. A deny rule written again is here once any device wrote it,
// or once its deletion is (deletion is final).
func (d *Device) notYetHere(c *Change) *Change {
	rec := d.data.records[c.Record]
	if c.Type == TypeDeny {
		if rec != nil && (rec.Exists || rec.Deleted) {
			return nil
		}
		return c
	}
	if rec == nil || rec.Deleted {
		return nil
	}
	var keep []Field
	for _, f := range c.Fields {
		if rec.Fields[f.Name].Value != f.Value {
			keep = append(keep, f)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	return &Change{Kind: kindRecord, Record: c.Record, Type: c.Type, Fields: keep}
}

// writeAgain writes the stricter values this device kept from past a cut
// as its own writes (SS 6.2, decided 2026-11-14). They apply by themselves
// on every device.
func (d *Device) writeAgain() (int, error) {
	todo := d.rewrite
	d.rewrite = nil
	n := 0
	for _, c := range todo {
		if c = d.notYetHere(c); c == nil {
			continue
		}
		if _, err := d.change(c); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// pastFloor applies the rule between floor and cut to a change of a
// removed device and keeps the person's view of it up to date. It
// returns what is kept, or nil.
func (d *Device) pastFloor(w *Write, c *Change, rep *Report) *Change {
	if _, removed := d.list.Removed[w.Writer]; !removed || w.Seq <= d.floorOf(w.Writer).Seq {
		return c
	}
	ref := w.Ref()
	kept := keptPastFloor(c)
	n := d.dropped[ref]
	switch {
	case kept == c:
		if n != nil {
			delete(d.dropped, ref)
			if n.pastCut {
				d.keptAgain[ref] = false
			}
		}
	case n == nil:
		d.countRevoked(ref, rep)
		d.dropped[ref] = &dropNote{}
	case n.pastCut:
		// It was dropped whole, and now its part that applies by itself
		// is kept. Approvals and waiting changes stay dropped.
		n.pastCut = false
		if kept != nil {
			d.keptAgain[ref] = false
		}
	}
	return kept
}

// countRevoked counts a dropped write once, however often it is served,
// and reports whether this was the first time.
func (d *Device) countRevoked(ref WriteRef, rep *Report) bool {
	if d.revoked[ref] {
		return false
	}
	d.revoked[ref] = true
	rep.Revoked++
	return true
}

// noteDropped keeps a write of a removed device past its cut for the
// person to see and confirm (SS 6.2: never dropped silently).
func (d *Device) noteDropped(ref WriteRef) {
	n := d.dropped[ref]
	switch {
	case n == nil:
		d.dropped[ref] = &dropNote{pastCut: true}
	case !n.pastCut:
		n.pastCut, n.confirmed = true, false
	}
	delete(d.keptAgain, ref)
}

// DroppedWrites lists the writes of removed devices that were not kept,
// wholly or in part, and that the person has not confirmed yet.
func (d *Device) DroppedWrites() []WriteRef {
	var out []WriteRef
	for ref, n := range d.dropped {
		if !n.confirmed {
			out = append(out, ref)
		}
	}
	slices.SortFunc(out, cmpRef)
	return out
}

// KeptAgain lists the writes of removed devices that were shown as not
// kept and are now kept, wholly or the part that applies by itself,
// because a signed summary from before the removal covers them, and that
// the person has not confirmed yet.
func (d *Device) KeptAgain() []WriteRef {
	var out []WriteRef
	for ref, confirmed := range d.keptAgain {
		if !confirmed {
			out = append(out, ref)
		}
	}
	slices.SortFunc(out, cmpRef)
	return out
}

// ConfirmDropped records that the person saw the dropped writes and the
// writes kept again.
func (d *Device) ConfirmDropped() {
	for _, n := range d.dropped {
		n.confirmed = true
	}
	for ref := range d.keptAgain {
		d.keptAgain[ref] = true
	}
}
