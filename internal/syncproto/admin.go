package syncproto

import (
	"fmt"
	"time"
)

// Remove takes devices off the list at their last write this device has
// seen, and starts the next account key generation sealed only to the
// devices that stay (SS 6.2, 7.1). A device added less than 7 days ago
// cannot remove an older one this way: it uses RemoveLater.
func (d *Device) Remove(targets ...DeviceID) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	rs := d.removals(targets)
	if d.selfYoung(rs) {
		return ErrYoungDevice
	}
	g, err := newGen(d.list.Gen.Gen + 1)
	if err != nil {
		return err
	}
	en := d.nextEntry(Body{Action: ActRemove, Removes: rs, Key: &g.KeyGen})
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	return d.startGen(en, g)
}

// startGen appends an entry that starts generation g, then seals g to the
// devices and kits the list now holds.
func (d *Device) startGen(en *Entry, g genKeys) error {
	if err := d.appendEntry(en); err != nil {
		return err
	}
	d.installGen(g)
	return d.uploadGen(g)
}

// selfYoung is the 7-day rule on this device's own clock, counted from
// when it first saw the entry that added it (or signed in its authority).
func (d *Device) selfYoung(rs []Removal) bool {
	me := d.list.Members[d.id]
	if me == nil || me.AddedAt == 1 {
		return false
	}
	if d.now().Sub(d.seen[d.list.Hashes[me.AddedAt-1]]) >= WaitYoung {
		return false
	}
	for _, r := range rs {
		if t := d.list.Members[r.Device]; t != nil && r.Device != d.id && t.AddedAt < me.AddedAt {
			return true
		}
	}
	return false
}

func (d *Device) removals(targets []DeviceID) []Removal {
	var rs []Removal
	for _, t := range targets {
		h := d.applied[t]
		rs = append(rs, Removal{Device: t, LastSeq: h.Seq, LastHash: h.Hash})
	}
	return rs
}

// RemoveLater asks for a removal that applies after 7 days unless another
// device cancels it: the way for a young device (SS 6.2), cancellable as
// SS 6.4 describes for kit waits. It returns the pending entry's number.
func (d *Device) RemoveLater(targets ...DeviceID) (uint32, error) {
	if err := d.refreshList(); err != nil {
		return 0, err
	}
	g, err := newGen(d.list.Gen.Gen + 1)
	if err != nil {
		return 0, err
	}
	inner := Body{Action: ActRemove, Removes: d.removals(targets), Key: &g.KeyGen}
	num, err := d.pending(inner, nil)
	if err == nil {
		d.pendingKeys[num] = g
	}
	return num, err
}

// pending appends a Pending entry signed by this device's authority key.
func (d *Device) pending(inner Body, extra func(*Entry) error) (uint32, error) {
	if d.keys.Authority == nil {
		return 0, ErrNoAuthority
	}
	en := d.nextEntry(Body{Action: ActPending, Inner: &inner})
	if extra != nil {
		if err := extra(en); err != nil {
			return 0, err
		}
	}
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return 0, err
	}
	return en.Num, d.appendEntry(en)
}

// ApplyPending applies this device's waiting change once its own clock
// says the wait is over. Other devices check the wait on their own clocks.
func (d *Device) ApplyPending(num uint32) error {
	if err := d.refreshList(); err != nil {
		return err
	}
	p := d.list.Pending[num]
	switch {
	case p == nil:
		return fmt.Errorf("%w: nothing waiting at entry %d", ErrChainBroken, num)
	case p.Cancelled:
		return ErrCancelled
	case p.Done:
		return nil
	case p.ReqDevice != d.id:
		return ErrNotAuthorized
	}
	if until := d.seen[d.list.Hashes[num-1]].Add(p.Wait); d.now().Before(until) {
		return fmt.Errorf("%w: until %s", ErrWaiting, until.Format(time.RFC3339))
	}
	en := d.nextEntry(Body{Action: ActApply, Ref: num})
	if err := en.signEntry(d.keys.Authority, RoleRequester, d.id, 0); err != nil {
		return err
	}
	if g, ok := d.pendingKeys[num]; ok {
		return d.startGen(en, g)
	}
	if err := d.appendEntry(en); err != nil {
		return err
	}
	return d.sealCurrentToKits()
}

// CancelPending drops a waiting change: any listed device with an
// authority key can (SS 6.4).
func (d *Device) CancelPending(num uint32) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	en := d.nextEntry(Body{Action: ActCancel, Ref: num})
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	return d.appendEntry(en)
}

// setKits makes n new kits. With old (a current kit, its key typed) they
// replace the current ones at once; the first kits need none.
func (d *Device) setKits(n int, old *Kit) ([]*Kit, error) {
	kits, recs, err := makeKits(n)
	if err != nil {
		return nil, err
	}
	en := d.nextEntry(Body{Action: ActSetKits, Kits: recs})
	if err := addNewKitSigs(en, kits); err != nil {
		return nil, err
	}
	var g genKeys
	if len(d.list.Kits) > 0 {
		if g, err = newGen(d.list.Gen.Gen + 1); err != nil {
			return nil, err
		}
		en.Body.Key = &g.KeyGen
	}
	if old != nil {
		idx := d.list.kitIndex(old.Record())
		if idx < 0 {
			return nil, ErrKitUnknown
		}
		if err := en.signEntry(old.signer(), RoleKit, DeviceID{}, uint8(idx)); err != nil {
			return nil, err
		}
	}
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return nil, err
	}
	if en.Body.Key != nil {
		return kits, d.startGen(en, g)
	}
	if err := d.appendEntry(en); err != nil {
		return nil, err
	}
	return kits, d.sealCurrentToKits()
}

// ReplaceKits makes up to 3 new kits; the current recovery key must be
// typed (old). Using or replacing one kit ends all of them (SS 6.4).
func (d *Device) ReplaceKits(n int, old *Kit) ([]*Kit, error) {
	if d.keys.Authority == nil {
		return nil, ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return nil, err
	}
	return d.setKits(n, old)
}

// ReplaceLostKits asks for new kits without the old key: it waits 7 days,
// shown on every device, and any device can cancel it (SS 6.4).
func (d *Device) ReplaceLostKits(n int) ([]*Kit, uint32, error) {
	if err := d.refreshList(); err != nil {
		return nil, 0, err
	}
	kits, recs, err := makeKits(n)
	if err != nil {
		return nil, 0, err
	}
	g, err := newGen(d.list.Gen.Gen + 1)
	if err != nil {
		return nil, 0, err
	}
	num, err := d.pending(Body{Action: ActSetKits, Kits: recs, Key: &g.KeyGen}, func(en *Entry) error {
		return addNewKitSigs(en, kits)
	})
	if err == nil {
		d.pendingKeys[num] = g
	}
	return kits, num, err
}

func makeKits(n int) ([]*Kit, []KitRecord, error) {
	if n < 1 || n > MaxKits {
		return nil, nil, fmt.Errorf("syncproto: 1 to %d kits", MaxKits)
	}
	var kits []*Kit
	var recs []KitRecord
	for range n {
		k, err := NewKit()
		if err != nil {
			return nil, nil, err
		}
		kits = append(kits, k)
		recs = append(recs, k.Record())
	}
	return kits, recs, nil
}

// addNewKitSigs has each new kit sign itself into the place of en (for a
// pending entry, the kits inside it).
func addNewKitSigs(en *Entry, kits []*Kit) error {
	for i, k := range kits {
		s, err := newKitSig(k, en.Prev, uint8(i))
		if err != nil {
			return err
		}
		en.Sigs = append(en.Sigs, s)
	}
	return nil
}

// sealCurrentToKits seals the current account key to every current kit.
func (d *Device) sealCurrentToKits() error {
	g := d.list.Gen
	acct := d.acctKeys[g.Gen]
	if acct == nil {
		return ErrNoKey
	}
	for _, k := range d.list.Kits {
		if err := d.sealToKit(genKeys{KeyGen: g, acct: acct}, k); err != nil {
			return err
		}
	}
	return nil
}

// SignInAuthority lets another device's new authority key count, after
// its face or finger changed (SS 6.1). A device never signs this for
// itself; the new key counts as a device added today for the 7-day rule.
func (d *Device) SignInAuthority(target DeviceID, newAuth []byte) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	en := d.nextEntry(Body{Action: ActReplaceAuthority, AuthOf: target, NewAuth: newAuth})
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	return d.appendEntry(en)
}

// UseAuthority sets this device's authority key, for example after Face ID
// changed. It counts on other devices only once SignInAuthority is in the
// list.
func (d *Device) UseAuthority(s Signer) { d.keys.Authority = s }
