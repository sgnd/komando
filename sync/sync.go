package komandosync

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"time"
)

// MaxSkew: a change stamped further in the future is stored but not
// applied until its time (SS 9).
const MaxSkew = 5 * time.Minute

// Report says what one sync did.
type Report struct {
	Applied    int   // writes checked, opened and merged
	Duplicates int   // writes served again (a replay): ignored
	Revoked    int   // writes by a removed device after its last accepted write: dropped
	Rejected   int   // approvals that do not verify, record changes recordFits refuses: dropped
	Deferred   int   // writes stamped in the future: kept for later
	Held       int   // writes and summaries naming list entries past a hold: read again after it
	Hold       *Hold // the list waits on this device's clock
	Alerts     []string
}

type staged struct {
	w *Write
	c *Change
}

// Sync pulls the list, keys, summaries and writes, checks all of it, and
// only then merges and signs a new summary. Any check that fails leaves
// the local state as it was (SS 9: data is used only when every write up
// to the newest summary is here).
func (d *Device) Sync() (*Report, error) {
	if d.kitToType != nil {
		return nil, ErrKitNotConfirmed
	}
	before := d.head
	rep, err := d.pull()
	if err != nil {
		return nil, err
	}
	if err := d.publishSummary(); err != nil {
		return nil, err
	}
	rep.Alerts = d.alerts(before)
	return rep, nil
}

// pull is Sync without signing a summary: check everything, then merge.
func (d *Device) pull() (*Report, error) {
	rep := &Report{}
	if err := d.refreshList(); err != nil {
		return nil, err
	}
	rep.Hold = d.list.Hold
	if err := d.dropRevoked(rep); err != nil {
		return nil, err
	}
	if err := d.loadKeys(); err != nil {
		return nil, err
	}
	target, best, err := d.readSummaries()
	if err != nil {
		return nil, err
	}
	stage, err := d.readWrites(rep)
	if err != nil {
		return nil, err
	}
	if err := d.checkComplete(target, stage); err != nil {
		return nil, err
	}
	d.commit(stage, rep)
	d.newest = target
	for id, s := range best {
		d.summaries[id], d.sumNum[id] = s, s.Num
	}
	return rep, nil
}

// dropRevoked handles a removal that names an earlier last write than
// this device already applied (it synced with the removed device before
// the remover did). SS says such writes are dropped by everyone; here they
// are, by merging again without them. Merging is commutative, so the
// result is what a device that never saw them holds.
func (d *Device) dropRevoked(rep *Report) error {
	drop := map[DeviceID]uint64{}
	for id, r := range d.list.Removed {
		if d.newest[id].Seq > r.LastSeq {
			d.newest[id] = Head{Device: id, Seq: r.LastSeq, Hash: r.LastHash}
		}
		if d.applied[id].Seq <= r.LastSeq {
			continue
		}
		if r.LastSeq > 0 && d.hashAt(id, r.LastSeq, nil) != r.LastHash {
			return fmt.Errorf("%w: last accepted write of a removed device differs", ErrFork)
		}
		drop[id] = r.LastSeq
		d.applied[id] = Head{Device: id, Seq: r.LastSeq, Hash: r.LastHash}
		d.hashes[id] = d.hashes[id][:r.LastSeq]
	}
	if len(drop) == 0 {
		return nil
	}
	old := d.log
	d.log, d.data = nil, newMergeState()
	for _, s := range old {
		if last, ok := drop[s.w.Writer]; ok && s.w.Seq > last {
			rep.Revoked++
			continue
		}
		d.applyChange(s.w, s.c, rep)
		d.log = append(d.log, s)
	}
	return nil
}

// readSummaries takes the newest valid summary of every listed device and
// merges them with the newest state this device remembers.
func (d *Device) readSummaries() (map[DeviceID]Head, map[DeviceID]*Summary, error) {
	target := maps.Clone(d.newest)
	best := map[DeviceID]*Summary{}
	for id, m := range d.list.Members {
		items, err := d.srv.Read(d.id, logSummaries(id))
		if err != nil {
			return nil, nil, err
		}
		// Only the newest counts, so only it is verified; a bad one stops
		// sync rather than falling back to an older one.
		var top *Summary
		for _, it := range items {
			s, err := ParseSummary(it)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: summary of %x", ErrBadSignature, id[:4])
			}
			if top == nil || s.Num > top.Num {
				top = s
			}
		}
		if top != nil && (top.Account != d.account || top.Signer != id ||
			!verifySig(parsePub(m.Rec.SyncPub), labelSummary, top.signedBytes(), top.Sig)) {
			return nil, nil, fmt.Errorf("%w: summary of %x", ErrBadSignature, id[:4])
		}
		if top == nil || top.Num < d.sumNum[id] {
			if d.sumNum[id] > 0 {
				return nil, nil, fmt.Errorf("%w: summaries of %x", ErrRollback, id[:4])
			}
			continue
		}
		if d.pastHold(top.ListNum) {
			continue // read again once the hold is over
		}
		if err := d.mergeSummary(top, target); err != nil {
			return nil, nil, err
		}
		best[id] = top
	}
	return target, best, nil
}

// pastHold reports whether a summary or write names a list entry this
// device holds back on its own clock. Devices that already waited have
// moved on; their newer summaries and writes wait here with the hold,
// instead of failing the whole sync.
func (d *Device) pastHold(listNum uint32) bool {
	return d.list.Hold != nil && listNum > d.head
}

// mergeSummary checks a summary against the list and folds its heads into
// target.
func (d *Device) mergeSummary(s *Summary, target map[DeviceID]Head) error {
	if s.ListNum > d.head {
		return fmt.Errorf("%w: a summary names list entry %d, the server gave %d", ErrListBehind, s.ListNum, d.head)
	}
	if s.ListNum == 0 || d.list.Hashes[s.ListNum-1] != s.ListHash {
		return fmt.Errorf("%w: a summary names another list entry %d", ErrFork, s.ListNum)
	}
	for _, h := range s.Heads {
		if r, removed := d.list.Removed[h.Device]; removed && h.Seq > r.LastSeq {
			h = Head{Device: h.Device, Seq: r.LastSeq, Hash: r.LastHash}
		}
		cur := target[h.Device]
		switch {
		case h.Seq > cur.Seq:
			target[h.Device] = h
		case h.Seq == cur.Seq && h.Seq > 0 && h.Hash != cur.Hash:
			return fmt.Errorf("%w: two different writes %d of one device", ErrFork, h.Seq)
		}
	}
	return nil
}

// readWrites fetches every device's new writes and checks each before it
// is opened: signature, place, chain, list entry (check first, open
// second, SS 7.2).
func (d *Device) readWrites(rep *Report) ([]staged, error) {
	own, err := d.srv.Read(d.id, logWrites(d.id))
	if err != nil {
		return nil, err
	}
	if uint64(len(own)) < d.ownSeq {
		return nil, fmt.Errorf("%w: own writes missing", ErrRollback)
	}
	var stage []staged
	ids := slices.SortedFunc(maps.Keys(d.list.Ever), func(a, b DeviceID) int { return bytes.Compare(a[:], b[:]) })
	for _, id := range ids {
		if id == d.id {
			continue
		}
		items, err := d.srv.Read(d.id, logWrites(id))
		if err != nil {
			return nil, err
		}
		got, err := d.readDeviceWrites(id, items, rep)
		if err != nil {
			return nil, err
		}
		stage = append(stage, got...)
	}
	return stage, nil
}

func (d *Device) readDeviceWrites(id DeviceID, items [][]byte, rep *Report) ([]staged, error) {
	var out []staged
	cur := d.applied[id]
	limit := ^uint64(0)
	r, removed := d.list.Removed[id]
	if removed {
		limit = r.LastSeq
	}
	var prev uint64
	for _, it := range items {
		w, err := ParseWrite(it)
		if err != nil || w.Writer != id {
			return nil, fmt.Errorf("%w: malformed write in the log of %x", ErrBadWrite, id[:4])
		}
		h := w.Hash()
		if w.Seq <= prev {
			rep.Duplicates++ // served twice in one answer: a replay
		}
		prev = max(prev, w.Seq)
		if w.Seq <= cur.Seq {
			if w.Seq == 0 || d.hashAt(id, w.Seq, out) != h {
				return nil, fmt.Errorf("%w: write %d of %x changed", ErrFork, w.Seq, id[:4])
			}
			continue
		}
		if w.Seq > limit {
			rep.Revoked++
			continue
		}
		if w.Seq != cur.Seq+1 || w.Prev != cur.Hash {
			return nil, fmt.Errorf("%w: write %d of %x out of order or after a gap", ErrMissingWrites, w.Seq, id[:4])
		}
		if removed && w.Seq == limit && h != r.LastHash {
			return nil, fmt.Errorf("%w: last accepted write of a removed device differs", ErrFork)
		}
		if d.pastHold(w.ListNum) {
			rep.Held++ // this one and the rest of the log, after the hold
			break
		}
		c, err := d.checkAndOpen(w)
		if err != nil {
			return nil, err
		}
		out = append(out, staged{w, c})
		cur = Head{Device: id, Seq: w.Seq, Hash: h}
	}
	return out, nil
}

// hashAt is the hash of a device's write seq, from what is applied or
// staged.
func (d *Device) hashAt(id DeviceID, seq uint64, stage []staged) Hash {
	if hs := d.hashes[id]; seq >= 1 && seq <= uint64(len(hs)) {
		return hs[seq-1]
	}
	for _, s := range stage {
		if s.w.Writer == id && s.w.Seq == seq {
			return s.w.Hash()
		}
	}
	return Hash{}
}

// checkAndOpen checks a write's place and signature, then opens it.
func (d *Device) checkAndOpen(w *Write) (*Change, error) {
	if w.Account != d.account || w.Vault != d.vaultID() {
		return nil, ErrAccountMismatch
	}
	if w.ListNum == 0 || w.ListNum > d.head {
		return nil, fmt.Errorf("%w: a write names list entry %d, the server gave %d", ErrListBehind, w.ListNum, d.head)
	}
	if d.list.Hashes[w.ListNum-1] != w.ListHash {
		return nil, fmt.Errorf("%w: a write names another list entry %d", ErrFork, w.ListNum)
	}
	rec := d.list.Ever[w.Writer]
	if d.list.FirstAt[w.Writer] > w.ListNum {
		return nil, fmt.Errorf("%w: written before the device was listed", ErrBadWrite)
	}
	if !verifySig(parsePub(rec.SyncPub), labelWrite, w.signedBytes(), w.Sig) {
		return nil, ErrBadSignature
	}
	// A write is sealed under the generation in force at the list entry it
	// names. (A device the server holds on an old entry still writes
	// under the old key: see finding 25 in sync-prototype.md.)
	if w.KeyGen != d.list.GenAt[w.ListNum-1] {
		return nil, fmt.Errorf("%w: sealed under key generation %d, entry %d has %d", ErrBadWrite, w.KeyGen, w.ListNum, d.list.GenAt[w.ListNum-1])
	}
	vk := d.vaultKeys[w.KeyGen]
	if vk == nil {
		return nil, ErrNoKey
	}
	p, err := openRecord(vk, w.header(), w.Body)
	if err != nil {
		return nil, err
	}
	return parseChange(p)
}

// checkComplete: every write up to the newest summary must be here.
func (d *Device) checkComplete(target map[DeviceID]Head, stage []staged) error {
	last := maps.Clone(d.applied)
	for _, s := range stage {
		last[s.w.Writer] = Head{Device: s.w.Writer, Seq: s.w.Seq}
	}
	for dev, h := range target {
		if last[dev].Seq < h.Seq {
			return fmt.Errorf("%w: %x has write %d, this device got %d", ErrMissingWrites, dev[:4], h.Seq, last[dev].Seq)
		}
		if h.Seq > 0 && d.hashAt(dev, h.Seq, stage) != h.Hash {
			return fmt.Errorf("%w: write %d of %x is not the one summarised", ErrFork, h.Seq, dev[:4])
		}
	}
	return nil
}

func (d *Device) commit(stage []staged, rep *Report) {
	for _, s := range stage {
		h := s.w.Hash()
		d.applied[s.w.Writer] = Head{Device: s.w.Writer, Seq: s.w.Seq, Hash: h}
		d.hashes[s.w.Writer] = append(d.hashes[s.w.Writer], h)
	}
	ready := append(d.deferred, stage...)
	d.deferred = nil
	limit := d.now().Add(MaxSkew).UnixMilli()
	for _, s := range ready {
		if r, ok := d.list.Removed[s.w.Writer]; ok && s.w.Seq > r.LastSeq {
			rep.Revoked++ // deferred, then its writer was removed
			continue
		}
		if s.w.Clock.Wall > limit {
			d.deferred = append(d.deferred, s)
			continue
		}
		d.observe(s.w.Clock)
		d.applyChange(s.w, s.c, rep)
		d.log = append(d.log, s)
	}
	rep.Applied = len(stage)
	rep.Deferred = len(d.deferred)
}

// summary builds this device's signed summary of what it holds.
func (d *Device) summary() (*Summary, error) {
	s := &Summary{
		Account: d.account, Signer: d.id, Num: d.sumNum[d.id] + 1, KeyGen: d.list.Gen.Gen,
		ListNum: d.head, ListHash: d.headHash, MinClient: minClient,
	}
	for _, id := range slices.SortedFunc(maps.Keys(d.applied), func(a, b DeviceID) int { return bytes.Compare(a[:], b[:]) }) {
		s.Heads = append(s.Heads, d.applied[id])
	}
	var err error
	s.Sig, err = sign(d.keys.Sync, labelSummary, s.signedBytes())
	return s, err
}

func (d *Device) publishSummary() error {
	s, err := d.summary()
	if err != nil {
		return err
	}
	if err := d.srv.Append(d.id, logSummaries(d.id), s.Marshal()); err != nil {
		return err
	}
	d.sumNum[d.id], d.summaries[d.id] = s.Num, s
	for _, h := range s.Heads {
		if h.Seq > d.newest[h.Device].Seq {
			d.newest[h.Device] = h
		}
	}
	return nil
}

// SummaryCode is this device's newest signed summary, to show as a QR code
// to a device beside it (SS 9: compare without the server).
func (d *Device) SummaryCode() []byte {
	if s := d.summaries[d.id]; s != nil {
		return s.Marshal()
	}
	return nil
}

// CheckPeer compares a summary read from another device's screen. A
// device the server has been holding back from finds out here.
func (d *Device) CheckPeer(code []byte) error {
	s, err := ParseSummary(code)
	if err != nil {
		return err
	}
	rec, ok := d.list.Ever[s.Signer]
	if !ok || s.Account != d.account || !verifySig(parsePub(rec.SyncPub), labelSummary, s.signedBytes(), s.Sig) {
		return ErrBadSignature
	}
	target := maps.Clone(d.newest)
	if err := d.mergeSummary(s, target); err != nil {
		return err
	}
	d.newest = target
	return d.checkComplete(target, nil)
}

func (d *Device) alerts(before uint32) []string {
	var out []string
	for id, m := range d.list.Members {
		if d.list.FirstAt[id] > before && m.AddedAt > before && id != d.id {
			out = append(out, fmt.Sprintf("A new device was added (entry %d)", d.list.FirstAt[id]))
		}
	}
	for _, num := range slices.Sorted(maps.Keys(d.list.Pending)) {
		p := d.list.Pending[num]
		if p.Done {
			continue
		}
		if p.Inner.Action == ActTakeover {
			out = append(out, fmt.Sprintf("entry %d: the recovery key was used to add a device; it applies after 24 hours unless cancelled", num))
		} else {
			out = append(out, fmt.Sprintf("entry %d: a waiting %s; any device can cancel it", num, p.Inner.Action))
		}
	}
	if h := d.list.Hold; h != nil {
		out = append(out, fmt.Sprintf("entry %d waits until %s: %s", h.Entry, h.Until.Format(time.RFC3339), h.Reason))
	}
	for _, en := range d.list.Entries[min(int(before), len(d.list.Entries)):] {
		if en.Body.Action != ActReplaceAuthority {
			continue
		}
		who := "another device"
		if en.Body.AuthOf == d.id {
			who = "this device; if you did not ask for it, someone holds this device's keys"
		}
		out = append(out, fmt.Sprintf("entry %d: a new authority key was signed in for %s", en.Num, who))
	}
	return out
}
