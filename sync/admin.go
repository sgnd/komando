package komandosync

import (
	"bytes"
	"fmt"
	"time"
)

// Remove takes devices off the list, recording their last write this
// device has seen as the floor, and starts the next account key generation
// sealed only to the devices that stay (SS 6.2, 7.1). A device added less
// than 7 days ago cannot remove an older one this way: it uses
// RemoveLater.
func (d *Device) Remove(targets ...DeviceID) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	rs := d.removals(targets)
	if d.selfYoung(targets) {
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
// A target is older when it was first listed before that entry.
func (d *Device) selfYoung(targets []DeviceID) bool {
	me := d.list.Members[d.id]
	if me == nil || me.AddedAt == 1 {
		return false
	}
	if d.now().Sub(d.seen[d.list.Hashes[me.AddedAt-1]]) >= WaitYoung {
		return false
	}
	for _, t := range targets {
		if d.list.Members[t] != nil && t != d.id && d.list.FirstAt[t] < me.AddedAt {
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

// RemoveLater asks for a removal that applies after 7 days unless a device
// with an authority key cancels it: the way for a young device (SS 6.2).
// It returns the pending entry's number.
func (d *Device) RemoveLater(targets ...DeviceID) (uint32, error) {
	if err := d.refreshList(); err != nil {
		return 0, err
	}
	return d.pending(Body{Action: ActRemove, Removes: d.removals(targets)}, nil)
}

// pending appends a Pending entry signed by this device's authority key.
func (d *Device) pending(inner Body, extra func(*Entry) error) (uint32, error) {
	if d.keys.Authority == nil {
		return 0, ErrNoAuthority
	}
	return d.pendingBy(inner, func(en *Entry) error {
		if extra != nil {
			if err := extra(en); err != nil {
				return err
			}
		}
		return en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0)
	})
}

// pendingBy appends a Pending entry that sign signs.
func (d *Device) pendingBy(inner Body, sign func(*Entry) error) (uint32, error) {
	en := d.nextEntry(Body{Action: ActPending, Inner: &inner})
	if err := sign(en); err != nil {
		return 0, err
	}
	return en.Num, d.appendEntry(en)
}

// ApplyPending applies this device's waiting change once its own clock
// says the wait is over. Other devices check the wait on their own clocks.
// The new account key is made now, not when the change was asked for, so
// a key change during the wait does not strand it.
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
	// A kit step on a device without Face ID, or a new authority key the
	// kit signed in, is applied with the asking device's sync key.
	signer := d.keys.Authority
	if bytes.Equal(p.Requester, d.rec.SyncPub) {
		signer = d.keys.Sync
	}
	if signer == nil {
		return ErrNoAuthority
	}
	en := d.nextEntry(Body{Action: ActApply, Ref: num})
	newKey := len(d.list.Kits) > 0
	switch p.Inner.Action {
	case ActRemove:
		newKey = len(d.list.stillListed(p.Inner.Removes)) > 0
	case ActReplaceAuthority:
		newKey = false
	}
	var g genKeys
	if newKey {
		var err error
		if g, err = newGen(d.list.Gen.Gen + 1); err != nil {
			return err
		}
		en.Body.Key = &g.KeyGen
	}
	if err := en.signEntry(signer, RoleRequester, d.id, 0); err != nil {
		return err
	}
	if newKey {
		return d.startGen(en, g)
	}
	if err := d.appendEntry(en); err != nil {
		return err
	}
	return d.sealCurrentToKits()
}

// CancelPending drops a waiting change: any listed device with an
// authority key can, never a kit (SS 6.2, 6.4). After a cancelled kit
// step the kit is known to be in someone else's hands, so this device
// asks the person to replace the kits at once (KitsAtRisk).
func (d *Device) CancelPending(num uint32) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	p := d.list.Pending[num]
	en := d.nextEntry(Body{Action: ActCancel, Ref: num})
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	if err := d.appendEntry(en); err != nil {
		return err
	}
	if p != nil && p.Kit {
		d.kitsAtRisk = true
	}
	return nil
}

// KitsAtRisk reports that this device cancelled a recovery-key step, so
// the person should replace the kits now (SS 6.4, "after a cancel").
func (d *Device) KitsAtRisk() bool { return d.kitsAtRisk }

// setKits makes n new kits: the first kits of an account, or, with old (a
// current kit, its key typed), new kits that replace the current ones at
// once while this device is the only one listed.
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
		if err := d.kitSign(en, old); err != nil {
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

// kitSign adds a current kit's signature to en.
func (d *Device) kitSign(en *Entry, k *Kit) error {
	idx := d.list.kitIndex(k.Record())
	if idx < 0 {
		return ErrKitUnknown
	}
	return en.signEntry(k.signer(), RoleKit, DeviceID{}, uint8(idx))
}

// ReplaceKits makes up to 3 new kits; the current recovery key must be
// typed (old). Using or replacing one kit ends all of them, and starts a
// new account key (SS 6.4). The kit signs it, so while another device is
// listed it waits 24 hours, and any device with an authority key can
// cancel it: then it returns the pending entry, to apply with
// ApplyPending. Alone on the list it applies at once and returns 0.
func (d *Device) ReplaceKits(n int, old *Kit) ([]*Kit, uint32, error) {
	if d.keys.Authority == nil {
		return nil, 0, ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return nil, 0, err
	}
	if old == nil {
		return nil, 0, fmt.Errorf("%w: type the current recovery key, or replace lost kits", ErrNotAuthorized)
	}
	if d.list.alone(d.id) {
		kits, err := d.setKits(n, old)
		return kits, 0, err
	}
	kits, recs, err := makeKits(n)
	if err != nil {
		return nil, 0, err
	}
	num, err := d.pending(Body{Action: ActSetKits, Kits: recs}, func(en *Entry) error {
		if err := addNewKitSigs(en, kits); err != nil {
			return err
		}
		return d.kitSign(en, old)
	})
	return kits, num, err
}

// ReplaceLostKits asks for new kits without the old key: it waits 7 days,
// shown on every device, and any device with an authority key can cancel
// it, never a kit (SS 6.4).
func (d *Device) ReplaceLostKits(n int) ([]*Kit, uint32, error) {
	if err := d.refreshList(); err != nil {
		return nil, 0, err
	}
	kits, recs, err := makeKits(n)
	if err != nil {
		return nil, 0, err
	}
	num, err := d.pending(Body{Action: ActSetKits, Kits: recs}, func(en *Entry) error {
		return addNewKitSigs(en, kits)
	})
	return kits, num, err
}

func makeKits(n int) ([]*Kit, []KitRecord, error) {
	if n < 1 || n > MaxKits {
		return nil, nil, fmt.Errorf("komandosync: 1 to %d kits", MaxKits)
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

// AuthRequest is a device asking for its new authority key to count, after
// its face or finger changed (SS 6.1). The device's sync key signs it, and
// the new key proves itself. The app carries it to another device, as a QR
// code or sealed through the server.
type AuthRequest struct {
	Device  DeviceID
	NewAuth []byte
	Ask     Sig // by the device's sync key
	Proof   Sig // by the new authority key
}

// AskAuthority makes the request for newKey and starts using it here. It
// counts on other devices only once another device signs it in.
func (d *Device) AskAuthority(newKey Signer) (*AuthRequest, error) {
	if err := d.refreshList(); err != nil {
		return nil, err
	}
	me := d.list.Members[d.id]
	if me == nil {
		return nil, ErrRemoved
	}
	r := &AuthRequest{Device: d.id, NewAuth: pubBytes(newKey.Public())}
	msg := authAskBytes(d.account, d.id, me.Rec.AuthPub, r.NewAuth)
	var err error
	if r.Ask, err = sign(d.keys.Sync, labelAuthAsk, msg); err != nil {
		return nil, err
	}
	if r.Proof, err = sign(newKey, labelAuthAsk, msg); err != nil {
		return nil, err
	}
	d.UseAuthority(newKey)
	return r, nil
}

// SignInAuthority lets another device's new authority key count. A device
// never signs this for itself; the new key counts as a device added today
// for the 7-day rule, and every device shows an alert. A device listed
// less than 7 days ago uses SignInAuthorityLater for an older device.
func (d *Device) SignInAuthority(r *AuthRequest) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	if d.selfYoung([]DeviceID{r.Device}) {
		return ErrYoungDevice
	}
	en := d.nextEntry(r.body())
	en.Sigs = r.sigs()
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	return d.appendEntry(en)
}

// SignInAuthorityLater is SignInAuthority as a change that waits 7 days,
// cancellable by any device with an authority key (SS 6.1, 6.2). It
// returns the pending entry; this device applies it with ApplyPending.
func (d *Device) SignInAuthorityLater(r *AuthRequest) (uint32, error) {
	if err := d.refreshList(); err != nil {
		return 0, err
	}
	return d.pending(r.body(), func(en *Entry) error {
		en.Sigs = append(en.Sigs, r.sigs()...)
		return nil
	})
}

// SignInAuthorityWithKit is the device that asked signing its own new
// authority key in with the recovery key, when no other device can (SS
// 6.1). While another device is listed it waits 24 hours, any device with
// an authority key can cancel it, and the new key signs nothing until this
// device applies it with ApplyPending; it returns the pending entry. Alone
// on the list it applies at once and returns 0.
func (d *Device) SignInAuthorityWithKit(k *Kit, r *AuthRequest) (uint32, error) {
	if r.Device != d.id {
		return 0, fmt.Errorf("%w: the device that asked uses the kit itself", ErrNotAuthorized)
	}
	if err := d.refreshList(); err != nil {
		return 0, err
	}
	sign := func(en *Entry) error {
		en.Sigs = append(en.Sigs, r.sigs()...)
		return d.kitSign(en, k)
	}
	if d.list.alone(d.id) {
		en := d.nextEntry(r.body())
		if err := sign(en); err != nil {
			return 0, err
		}
		return 0, d.appendEntry(en)
	}
	return d.pendingBy(r.body(), sign)
}

func (r *AuthRequest) body() Body {
	return Body{Action: ActReplaceAuthority, AuthOf: r.Device, NewAuth: r.NewAuth}
}

func (r *AuthRequest) sigs() []EntrySig {
	return []EntrySig{{Role: RoleAuthAsk, Device: r.Device, Sig: r.Ask}, {Role: RoleAuthProof, Device: r.Device, Sig: r.Proof}}
}

// UseAuthority sets this device's authority key, for example after Face ID
// changed. It counts on other devices only once SignInAuthority is in the
// list.
func (d *Device) UseAuthority(s Signer) { d.keys.Authority = s }
