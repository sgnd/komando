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
	Revoked    int   // writes by a removed device past the writes that count (SS 6.2): dropped
	Rejected   int   // approvals that do not verify, record changes recordFits refuses: dropped
	Deferred   int   // writes stamped in the future: kept for later
	Held       int   // writes and summaries naming list entries past a hold: read again after it
	OldKey     int   // writes sealed under a key generation this device already knew was replaced (SS 7.1)
	Rewritten  int   // stricter values kept from past a removed device's cut, written again as this device's own (SS 6.2)
	Refused    int   // snapshots that did not match this device's data: refused, the writes kept (SS 9)
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
	rep, err := d.pull()
	if err != nil {
		return nil, err
	}
	if rep.Rewritten, err = d.writeAgain(); err != nil {
		return nil, err
	}
	if err := d.checkSnapshots(rep); err != nil {
		return nil, err
	}
	if err := d.publishSummary(); err != nil {
		return nil, err
	}
	d.rebase()
	before := d.head
	if d.alertDue {
		before, d.alertDue = d.alertFrom, false
	}
	rep.Alerts = d.alerts(before)
	if rep.Refused > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d snapshots did not match this device's data; they were refused and the writes are kept", rep.Refused))
	}
	if rep.OldKey > 0 {
		rep.Alerts = append(rep.Alerts, fmt.Sprintf("%d changes were sealed under a key from before a removal; a removed device can read them", rep.OldKey))
	}
	return rep, nil
}

// pull is Sync without signing a summary: check everything, then merge.
func (d *Device) pull() (*Report, error) {
	rep := &Report{}
	// A device that already holds a signed state alerts on writes sealed
	// under a generation it knew was replaced (SS 7.1). A device catching
	// up from nothing does not: all of history is new to it. When the list
	// moved outside Sync, what it knew is the generation at the entry it
	// held before that move (SS 6.3).
	knownGen := uint32(0)
	if d.list != nil && d.summaries[d.id] != nil {
		knownGen = d.list.Gen.Gen
		if d.alertDue && d.alertFrom > 0 {
			knownGen = d.list.GenAt[d.alertFrom-1]
		}
	}
	if err := d.refreshList(); err != nil {
		return nil, err
	}
	rep.Hold = d.list.Hold
	if err := d.computeCuts(); err != nil {
		return nil, err
	}
	if err := d.dropRevoked(rep); err != nil {
		return nil, err
	}
	if err := d.loadKeys(); err != nil {
		return nil, err
	}
	if err := d.startFromSnapshot(); err != nil {
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
	for _, s := range stage {
		if s.w.KeyGen < knownGen {
			rep.OldKey++
		}
	}
	d.commit(stage, rep)
	d.newest = target
	for id, s := range best {
		d.summaries[id], d.sumNum[id] = s, s.Num
	}
	return rep, nil
}

// readSummaries takes the newest valid summary of every listed device and
// merges them with the newest state this device remembers.
func (d *Device) readSummaries() (map[DeviceID]Head, map[DeviceID]*Summary, error) {
	target := maps.Clone(d.newest)
	best := map[DeviceID]*Summary{}
	for id, m := range d.list.Members {
		log, err := d.summaryLog(id)
		if err != nil {
			return nil, nil, err
		}
		// Only the newest counts, so only it is verified; a bad one stops
		// sync rather than falling back to an older one.
		var top *Summary
		for _, s := range log {
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
	// Every write of a removed device that counts must be here too.
	for id, c := range d.cuts {
		if c.Seq > target[id].Seq {
			target[id] = c
		}
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
		if _, removed := d.list.Removed[h.Device]; removed {
			if c := d.cuts[h.Device]; h.Seq > c.Seq {
				// A summary from after the removal holds only writes that
				// a summary from before it showed: the server holds that
				// one back.
				if s.ListNum >= d.list.RemInfo[h.Device].At {
					return fmt.Errorf("%w: a summary covers writes of a removed device that no summary from before the removal shows", ErrMissingWrites)
				}
				h = c
			}
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
	// Own writes a confirmed snapshot holds may be gone; the newest must
	// be there.
	if d.ownSeq > d.baseHeads[d.id].Seq {
		var top uint64
		for _, it := range own {
			if w, err := ParseWrite(it); err == nil && w.Writer == d.id && w.Hash() == d.hashAt(d.id, w.Seq, nil) {
				top = max(top, w.Seq)
			}
		}
		if top < d.ownSeq {
			return nil, fmt.Errorf("%w: own writes missing", ErrRollback)
		}
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
	cut := d.cuts[id]
	if removed {
		limit = cut.Seq
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
		if w.Seq < d.baseHeads[id].Seq {
			continue // held by the snapshot this device builds on
		}
		if w.Seq <= cur.Seq {
			if w.Seq == 0 || d.hashAt(id, w.Seq, out) != h {
				return nil, fmt.Errorf("%w: write %d of %x changed", ErrFork, w.Seq, id[:4])
			}
			continue
		}
		if w.Seq > limit {
			if verifySig(parsePub(d.list.Ever[id].SyncPub), labelWrite, w.signedBytes(), w.Sig) && d.countRevoked(w.Ref(), rep) {
				d.noteDropped(w.Ref())
			}
			continue
		}
		if w.Seq != cur.Seq+1 || w.Prev != cur.Hash {
			return nil, fmt.Errorf("%w: write %d of %x out of order or after a gap", ErrMissingWrites, w.Seq, id[:4])
		}
		if removed && ((w.Seq == limit && h != cut.Hash) || (w.Seq == r.LastSeq && h != r.LastHash)) {
			return nil, fmt.Errorf("%w: a recorded write of a removed device differs", ErrFork)
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
	b := d.baseHeads[id]
	if seq >= 1 && seq == b.Seq {
		return b.Hash
	}
	if hs := d.hashes[id]; seq > b.Seq && seq-b.Seq <= uint64(len(hs)) {
		return hs[seq-b.Seq-1]
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
		if h.Seq > 0 && h.Seq >= d.baseHeads[dev].Seq && d.hashAt(dev, h.Seq, stage) != h.Hash {
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
		if _, ok := d.list.Removed[s.w.Writer]; ok && s.w.Seq > d.cuts[s.w.Writer].Seq {
			if d.countRevoked(s.w.Ref(), rep) { // deferred, then its writer was removed
				d.noteDropped(s.w.Ref())
			}
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
	if prev := d.summaries[d.id]; prev != nil {
		s.Prev = prev.Hash()
	}
	if d.snap != nil {
		s.Snap = d.snap.Hash()
	}
	s.Base = d.baseHash
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
		switch {
		case p.Inner.Action == ActTakeover:
			out = append(out, fmt.Sprintf("entry %d: the recovery key was used to take the account over on a new device; it applies after 24 hours unless a device with Face ID or Touch ID cancels it", num))
		case p.Kit:
			out = append(out, fmt.Sprintf("entry %d: the recovery key was used (%s); it applies after 24 hours unless a device with Face ID or Touch ID cancels it", num, p.Inner.Action))
		default:
			out = append(out, fmt.Sprintf("entry %d: a waiting %s; any device with Face ID or Touch ID can cancel it", num, p.Inner.Action))
		}
	}
	if n := len(d.DroppedWrites()); n > 0 {
		out = append(out, fmt.Sprintf("%d changes from removed devices were not kept; check them and confirm", n))
	}
	if n := len(d.KeptAgain()); n > 0 {
		out = append(out, fmt.Sprintf("%d changes from removed devices that were shown as not kept are now kept; check them and confirm", n))
	}
	if d.kitsAtRisk {
		out = append(out, "the recovery kit is in someone else's hands: replace the kits now")
	}
	if h := d.list.Hold; h != nil {
		out = append(out, fmt.Sprintf("entry %d waits until %s: %s", h.Entry, h.Until.Format(time.RFC3339), h.Reason))
	}
	for _, en := range d.list.Entries[min(int(before), len(d.list.Entries)):] {
		of := en.Body.AuthOf
		switch en.Body.Action {
		case ActReplaceAuthority:
		case ActApply: // a sign-in that waited
			p := d.list.Pending[en.Body.Ref]
			if p == nil || p.Inner.Action != ActReplaceAuthority {
				continue
			}
			of = p.Inner.AuthOf
		default:
			continue
		}
		who := "another device"
		if of == d.id {
			who = "this device; if you did not ask for it, someone holds this device's keys"
		}
		out = append(out, fmt.Sprintf("entry %d: a new authority key was signed in for %s", en.Num, who))
	}
	return out
}
