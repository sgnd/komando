package komandosync

import (
	"fmt"
	"maps"
	"slices"
	"time"
)

// Recovery is a new device using a recovery kit when no other device is
// at hand (SS 6.4). It can read at once; it takes the account over (every
// other device removed, a new account key, new kits) only after the
// 24-hour wait, and any live device can cancel it before that.
type Recovery struct {
	Dev  *Device
	Info RecoveryInfo
	kit  *Kit
	num  uint32
	kits []*Kit
}

// RecoveryInfo is what the device shows from signed data before it goes
// on: "Last change by MacBook on 3 Nov, 4 devices, 212 records. Is this
// right?"
type RecoveryInfo struct {
	Devices    int
	Records    int
	LastWriter DeviceID
	LastWrite  time.Time
}

// OpenWithKit checks the chain from entry 1, refuses unless this kit is a
// current kit of it, opens the account key sealed to the kit, checks it
// against the key ID, and reads everything.
func OpenWithKit(dev *Device, kit *Kit) (*Recovery, error) {
	entries, err := readList(dev.srv, dev.id, dev.seen, dev.now())
	if err != nil {
		return nil, err
	}
	// The device remembers nothing, so nothing is newer to compare with
	// (SS 4: only the date and counts shown to the person).
	st, err := checkChain(entries, clockView{now: dev.now(), trustUpTo: uint32(len(entries)),
		seen: func(uint32) time.Time { return dev.now() }})
	if err != nil {
		return nil, err
	}
	if st.kitIndex(kit.Record()) < 0 {
		return nil, ErrKitUnknown
	}
	dev.account, dev.trustUpTo = st.Account, st.Head
	if err := dev.refreshList(); err != nil {
		return nil, err
	}
	g := dev.list.Gen
	ct, err := dev.srv.Get(dev.id, blobKitKey(g.KeyID, kit.Record()))
	if err != nil {
		return nil, err
	}
	if ct == nil {
		return nil, ErrNoKey
	}
	acct, err := kit.open(infoKit(dev.account, g.Gen, kit.Record()), ct)
	if err != nil {
		return nil, ErrNoKey
	}
	if err := dev.installOpened(g, acct); err != nil {
		return nil, err
	}
	if _, err := dev.pull(); err != nil {
		return nil, err
	}
	r := &Recovery{Dev: dev, kit: kit}
	r.Info = dev.recoveryInfo()
	return r, nil
}

func (d *Device) recoveryInfo() RecoveryInfo {
	info := RecoveryInfo{Devices: len(d.list.Members), Records: d.Records()}
	var best HLC
	for _, rec := range d.data.records {
		for _, f := range rec.Fields {
			if best.Less(f.Clock) {
				best = f.Clock
			}
		}
	}
	info.LastWriter, info.LastWrite = best.Dev, time.UnixMilli(best.Wall)
	return info
}

// Begin signs the takeover with the kit and the new device's keys and
// puts it on the list as a waiting change.
func (r *Recovery) Begin(newKits int) error {
	d := r.Dev
	kits, recs, err := makeKits(newKits)
	if err != nil {
		return err
	}
	inner := Body{Action: ActTakeover, Devices: []DeviceRecord{d.rec}, Removes: d.removals(d.memberIDs()), Kits: recs}
	en := d.nextEntry(Body{Action: ActPending, Inner: &inner})
	js, err := joinSigs(d.keys, &d.rec, 0)
	if err != nil {
		return err
	}
	en.Sigs = js
	if err := addNewKitSigs(en, kits); err != nil {
		return err
	}
	if err := d.kitSign(en, r.kit); err != nil {
		return err
	}
	if err := d.appendEntry(en); err != nil {
		return err
	}
	r.num, r.kits = en.Num, kits
	return nil
}

func (d *Device) memberIDs() []DeviceID {
	return slices.SortedFunc(maps.Keys(d.list.Members), func(a, b DeviceID) int { return slices.Compare(a[:], b[:]) })
}

// Pending is the list entry of the waiting takeover.
func (r *Recovery) Pending() uint32 { return r.num }

// Finish applies the takeover once this device's clock says 24 hours
// passed and nobody cancelled. It returns the new kits.
func (r *Recovery) Finish() ([]*Kit, error) {
	d := r.Dev
	// The list first: a takeover that ended says so, before the keys a
	// device that is not listed yet cannot open.
	if err := d.refreshList(); err != nil {
		return nil, err
	}
	p := d.list.Pending[r.num]
	if p == nil {
		return nil, fmt.Errorf("%w: the takeover is not on the list", ErrChainBroken)
	}
	switch {
	case p.Cancelled:
		return nil, ErrCancelled
	case p.KitGone:
		return nil, ErrKitReplaced
	}
	if until := d.seen[d.list.Hashes[r.num-1]].Add(WaitRecovery); d.now().Before(until) {
		return nil, fmt.Errorf("%w: until %s", ErrWaiting, until.Format(time.RFC3339))
	}
	if _, err := d.pull(); err != nil {
		return nil, err
	}
	// Writes the old devices made during the wait are kept: the apply
	// names their newest writes. The new key is made now.
	g, err := newGen(d.list.Gen.Gen + 1)
	if err != nil {
		return nil, err
	}
	en := d.nextEntry(Body{Action: ActApply, Ref: r.num, Removes: d.removals(d.memberIDs()), Key: &g.KeyGen})
	if err := en.signEntry(d.keys.Authority, RoleRequester, d.id, 0); err != nil {
		return nil, err
	}
	d.joined = true
	if err := d.startGen(en, g); err != nil {
		return nil, err
	}
	return r.kits, d.writeInfo()
}

// RecoveryStep is the kit used on a device already on the list, such as a
// Mac without Touch ID after the iPhone was lost (SS 6.4): the recovery
// key and this device's sync key sign one entry that removes the chosen
// devices, and on apply starts a new account key and ends the old kit. It
// replaces the kits, so while another device is listed it waits 24 hours,
// and any device with an authority key can cancel it: then it returns the
// pending entry, which this device applies with ApplyPending. Alone on the
// list it applies at once and returns 0.
func (d *Device) RecoveryStep(kit *Kit, remove []DeviceID, newKits int) ([]*Kit, uint32, error) {
	if err := d.refreshList(); err != nil {
		return nil, 0, err
	}
	if d.list.kitIndex(kit.Record()) < 0 {
		return nil, 0, ErrKitUnknown
	}
	kits, recs, err := makeKits(newKits)
	if err != nil {
		return nil, 0, err
	}
	sign := func(en *Entry) error {
		if err := addNewKitSigs(en, kits); err != nil {
			return err
		}
		if err := d.kitSign(en, kit); err != nil {
			return err
		}
		return en.signEntry(d.keys.Sync, RoleDevice, d.id, 0)
	}
	body := Body{Action: ActRecoveryStep, Removes: d.removals(remove), Kits: recs}
	if !d.list.alone(d.id) {
		num, err := d.pendingBy(body, sign)
		return kits, num, err
	}
	g, err := newGen(d.list.Gen.Gen + 1)
	if err != nil {
		return nil, 0, err
	}
	body.Key = &g.KeyGen
	en := d.nextEntry(body)
	if err := sign(en); err != nil {
		return nil, 0, err
	}
	return kits, 0, d.startGen(en, g)
}
