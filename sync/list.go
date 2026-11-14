package komandosync

import (
	"time"
)

// Action is what a device-list entry does (SS 6.2).
type Action uint8

// The actions. A change that must wait (a recovery that adds a device, a
// young device removing an older one, replacing a lost kit) is a Pending
// entry holding the change, later followed by an Apply or a Cancel entry.
const (
	ActCreate           Action = 1 + iota // entry 1: first device and account key 1
	ActSetKits                            // add the first kits, or replace them
	ActAddDevice                          // a device let in by an authority key
	ActRemove                             // remove devices, new account key
	ActReplaceAuthority                   // a device's new authority key, signed by another
	ActRecoveryStep                       // the kit on a listed device: remove, new key, new kits
	ActTakeover                           // the kit on a new device (only inside Pending)
	ActPending                            // a change that waits
	ActApply                              // the waited change takes effect; it carries the new key
	ActCancel                             // the waited change is dropped
)

func (a Action) String() string {
	names := [...]string{"", "create", "set-kits", "add-device", "remove", "replace-authority",
		"recovery-step", "takeover", "pending", "apply", "cancel"}
	if int(a) < len(names) && a != 0 {
		return names[a]
	}
	return "unknown"
}

// The waits. Each device counts them from the moment it first received the
// entry itself, on its own clock (SS 6.2 "who counts the days").
const (
	WaitRecovery  = 24 * time.Hour     // SS 6.4: a recovery-key step that adds a device
	WaitYoung     = 7 * 24 * time.Hour // SS 6.2: the 7-day rule
	WaitKitLost   = 7 * 24 * time.Hour // SS 6.4: replacing a lost kit without the key
	PairingWindow = 10 * time.Minute   // spec 5.3
	MaxKits       = 3                  // spec 5.4
)

// Removal records a removed device and its last accepted write (SS 6.2).
type Removal struct {
	Device   DeviceID
	LastSeq  uint64
	LastHash Hash
}

// KeyGen is one account key generation as the list holds it: its number,
// its key ID and the public account sealing key (SS 6.2, 7.1).
type KeyGen struct {
	Gen        uint32
	KeyID      [16]byte
	SealingPub []byte
}

// KitRecord is a recovery kit as the list holds it: the public halves of
// the signing and sealing keys derived from the recovery key.
type KitRecord struct {
	SignPub []byte
	SealPub []byte
}

// Body is the signed content of an entry, other than its number and the
// hash before it. Each action uses some of the fields; the rest stay empty,
// and checkShape refuses a field an action does not use.
type Body struct {
	Action  Action
	Devices []DeviceRecord
	Removes []Removal
	Key     *KeyGen
	Kits    []KitRecord
	AuthOf  DeviceID // ActReplaceAuthority
	NewAuth []byte   // ActReplaceAuthority
	Ref     uint32   // ActApply, ActCancel: the pending entry
	Inner   *Body    // ActPending
}

// SigRole says which key made a signature on an entry.
type SigRole uint8

// The roles.
const (
	RoleAuthority SigRole = 1 + iota // a listed device's authority key (Device)
	RoleKit                          // a current recovery kit (Index into the kit set)
	RoleJoinSync                     // a new device proves its sync key (Index into Devices)
	RoleJoinAuth                     // a new device proves its authority key
	RoleNewKit                       // a new kit binds itself to this place (Index into Kits)
	RoleRequester                    // the device that asked for a pending change applies it
	RoleAuthAsk                      // a device's sync key asks for its new authority key (over authAskBytes)
	RoleAuthProof                    // the new authority key proves itself (over authAskBytes)
	RoleDevice                       // a listed device's sync key (a recovery step names its device)
)

// EntrySig is one signature on an entry.
type EntrySig struct {
	Role   SigRole
	Device DeviceID
	Index  uint8
	Sig    Sig
}

// Entry is one link of the device list.
type Entry struct {
	Num  uint32
	Prev Hash
	Body Body
	Sigs []EntrySig
}

func (b *Body) encode(e *enc) {
	e.u8(uint8(b.Action))
	e.u32(uint32(len(b.Devices)))
	for i := range b.Devices {
		b.Devices[i].encode(e)
	}
	e.u32(uint32(len(b.Removes)))
	for _, r := range b.Removes {
		e.raw(r.Device[:])
		e.u64(r.LastSeq)
		e.raw(r.LastHash[:])
	}
	e.bool(b.Key != nil)
	if b.Key != nil {
		e.u32(b.Key.Gen)
		e.raw(b.Key.KeyID[:])
		e.bytes(b.Key.SealingPub)
	}
	e.u32(uint32(len(b.Kits)))
	for _, k := range b.Kits {
		e.bytes(k.SignPub)
		e.bytes(k.SealPub)
	}
	e.raw(b.AuthOf[:])
	e.bytes(b.NewAuth)
	e.u32(b.Ref)
	e.bool(b.Inner != nil)
	if b.Inner != nil {
		b.Inner.encode(e)
	}
}

func decodeBody(d *dec, depth int) Body {
	var b Body
	b.Action = Action(d.u8())
	for range d.count(16) {
		b.Devices = append(b.Devices, decodeDeviceRecord(d))
	}
	for range d.count(256) {
		var r Removal
		d.fixed(r.Device[:])
		r.LastSeq = d.u64()
		d.fixed(r.LastHash[:])
		b.Removes = append(b.Removes, r)
	}
	if d.bool() {
		k := &KeyGen{Gen: d.u32()}
		d.fixed(k.KeyID[:])
		k.SealingPub = d.bytes()
		b.Key = k
	}
	for range d.count(MaxKits) {
		b.Kits = append(b.Kits, KitRecord{SignPub: d.bytes(), SealPub: d.bytes()})
	}
	d.fixed(b.AuthOf[:])
	b.NewAuth = d.bytes()
	b.Ref = d.u32()
	if d.bool() {
		if depth > 0 {
			d.fail()
			return b
		}
		in := decodeBody(d, depth+1)
		b.Inner = &in
	}
	return b
}

// signedBytes is what every signature on the entry covers and what its
// hash covers: number, previous hash and body, never the signatures (SS
// 7.2: signatures never feed a hash).
func (en *Entry) signedBytes() []byte {
	var e enc
	e.u32(en.Num)
	e.raw(en.Prev[:])
	en.Body.encode(&e)
	return e.b
}

// Hash is the entry's hash. The account ID is the hash of entry 1.
func (en *Entry) Hash() Hash { return sum(labelEntryHash, en.signedBytes()) }

// Marshal is the entry as stored on the server.
func (en *Entry) Marshal() []byte {
	var e enc
	e.raw(en.signedBytes())
	e.u32(uint32(len(en.Sigs)))
	for _, s := range en.Sigs {
		e.u8(uint8(s.Role))
		e.raw(s.Device[:])
		e.u8(s.Index)
		e.raw(s.Sig[:])
	}
	return e.b
}

// ParseEntry reads a stored entry.
func ParseEntry(b []byte) (*Entry, error) {
	d := dec{b: b}
	en := &Entry{Num: d.u32()}
	d.fixed(en.Prev[:])
	en.Body = decodeBody(&d, 0)
	for range d.count(32) {
		var s EntrySig
		s.Role = SigRole(d.u8())
		d.fixed(s.Device[:])
		s.Index = d.u8()
		d.fixed(s.Sig[:])
		en.Sigs = append(en.Sigs, s)
	}
	if err := d.done(); err != nil {
		return nil, err
	}
	return en, nil
}

// signEntry adds a signature of the given role over the entry.
func (en *Entry) signEntry(s Signer, role SigRole, dev DeviceID, idx uint8) error {
	sig, err := sign(s, labelEntry, en.signedBytes())
	if err != nil {
		return err
	}
	en.Sigs = append(en.Sigs, EntrySig{Role: role, Device: dev, Index: idx, Sig: sig})
	return nil
}

// joinSigs are the new device's proofs that it holds the keys it names.
// They cover the device record only: the new device does not know the
// account or the entry yet when it makes them (see sync-prototype.md).
func joinSigs(keys *DeviceKeys, rec *DeviceRecord, idx uint8) ([]EntrySig, error) {
	id := rec.ID()
	s, err := sign(keys.Sync, labelJoin, rec.bytes())
	if err != nil {
		return nil, err
	}
	out := []EntrySig{{Role: RoleJoinSync, Device: id, Index: idx, Sig: s}}
	if keys.Authority != nil {
		a, err := sign(keys.Authority, labelJoin, rec.bytes())
		if err != nil {
			return nil, err
		}
		out = append(out, EntrySig{Role: RoleJoinAuth, Device: id, Index: idx, Sig: a})
	}
	return out, nil
}

// authAskBytes is what a device signs to ask for a new authority key, with
// its sync key and with the new key. It names the key it replaces, so an
// old request cannot be replayed once the key changed again.
func authAskBytes(account Hash, dev DeviceID, oldAuth, newAuth []byte) []byte {
	var e enc
	e.raw(account[:])
	e.raw(dev[:])
	e.bytes(oldAuth)
	e.bytes(newAuth)
	return e.b
}

// newKitSig is a new kit's signature over the hash of the entry before and
// its own record, so a kit belongs to exactly one place in one account.
func newKitSig(k *Kit, prev Hash, idx uint8) (EntrySig, error) {
	var e enc
	e.raw(prev[:])
	r := k.Record()
	e.bytes(r.SignPub)
	e.bytes(r.SealPub)
	s, err := sign(k.signer(), labelNewKit, e.b)
	return EntrySig{Role: RoleNewKit, Index: idx, Sig: s}, err
}

func verifyNewKitSig(rec KitRecord, prev Hash, sig Sig) bool {
	var e enc
	e.raw(prev[:])
	e.bytes(rec.SignPub)
	e.bytes(rec.SealPub)
	return verifySig(parsePub(rec.SignPub), labelNewKit, e.b, sig)
}
