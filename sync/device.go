package komandosync

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Device is one install of the Mac, iPhone or iPad app, as the sync
// engine sees it.
type Device struct {
	Name     string
	keys     *DeviceKeys
	rec      DeviceRecord
	id       DeviceID
	srv      Server
	now      func() time.Time
	infoSalt []byte

	// What the Keychain keeps, on this device only (SS 9): the account,
	// the newest list entry, when each entry was first seen, this
	// device's own write number, and the newest state seen.
	account    Hash
	joined     bool
	head       uint32
	headHash   Hash
	seen       map[Hash]time.Time
	trustUpTo  uint32
	ownSeq     uint64
	ownHash    Hash
	newest     map[DeviceID]Head
	sumNum     map[DeviceID]uint64
	kitToType  *Kit                  // set until the person types part of the kit back
	answered   map[Hash]bool         // pairing codes this device answered: one try each
	kitsAtRisk bool                  // this device cancelled a recovery-key step
	cuts       map[DeviceID]Head     // per removed device, its newest write that counts
	cutBy      map[DeviceID]DeviceID // per removed device, whose summary set its cut
	ruled      map[DeviceID]bool     // removed devices whose rules the merged data follows
	dropped    map[WriteRef]*dropNote
	keptAgain  map[WriteRef]bool // dropped writes a raised cut keeps after all; true once a person confirmed
	revoked    map[WriteRef]bool // dropped writes already counted in a Report
	rewrite    []*Change         // stricter values kept from past a cut, to write again as this device's own

	// The list can move forward outside Sync (a secret write, a removal,
	// a pairing). Sync alerts on everything since the first such move it
	// has not handled yet (SS 6.3, 7.1).
	alertFrom uint32
	alertDue  bool

	acctKeys  map[uint32][]byte
	vaultKeys map[uint32][]byte

	list      *ListState
	applied   map[DeviceID]Head
	hashes    map[DeviceID][]Hash // per device, the hashes of its writes after baseHeads
	base      *mergeState         // the state of the snapshot this device builds on; nil: none
	baseHeads map[DeviceID]Head   // the writes that snapshot holds
	baseHash  Hash                // the hash of that snapshot
	baseSnap  *Snapshot           // that snapshot: every current device named it, so writes it holds may go
	snap      *Snapshot           // the newest snapshot this device accepted; its summaries name it
	snapNum   uint64              // this device's own snapshots, counted
	refused   map[Hash]bool       // snapshots that did not match this device's data
	summaries map[DeviceID]*Summary
	data      *mergeState
	log       []staged // every applied change, to merge again without some
	hlc       HLC
	deferred  []staged

	// AutoApprove: a device with an authority key collects the person's
	// yes while editing (SS 8.1), so its own waiting changes carry it.
	AutoApprove bool

	// ConfirmUnchecked asks the person "could not check for removed
	// devices; save anyway?" when the list cannot be read before a secret
	// is sealed (SS 7.1). Nil means no.
	ConfirmUnchecked func(err error) bool
}

// NewDevice prepares a device with its keys. It belongs to no account
// until CreateAccount, a pairing or a recovery.
func NewDevice(name string, keys *DeviceKeys, srv Server, now func() time.Time) *Device {
	d := &Device{
		Name: name, keys: keys, srv: srv, now: now, AutoApprove: true,
		seen: map[Hash]time.Time{}, answered: map[Hash]bool{}, newest: map[DeviceID]Head{}, sumNum: map[DeviceID]uint64{},
		acctKeys: map[uint32][]byte{}, vaultKeys: map[uint32][]byte{},
		applied: map[DeviceID]Head{}, hashes: map[DeviceID][]Hash{}, summaries: map[DeviceID]*Summary{},
		data: newMergeState(), cuts: map[DeviceID]Head{}, cutBy: map[DeviceID]DeviceID{}, ruled: map[DeviceID]bool{},
		dropped: map[WriteRef]*dropNote{}, keptAgain: map[WriteRef]bool{}, revoked: map[WriteRef]bool{}, baseHeads: map[DeviceID]Head{}, refused: map[Hash]bool{},
	}
	d.rec = DeviceRecord{SyncPub: pubBytes(keys.Sync.Public()), UnwrapPub: keys.Unwrap.PublicKey()}
	if keys.Authority != nil {
		d.rec.AuthPub = pubBytes(keys.Authority.Public())
	}
	d.infoSalt = randomBytes(infoSaltSize)
	d.rec.InfoHash = deviceInfoHash(d.infoSalt, name)
	d.id = d.rec.ID()
	d.hlc.Dev = d.id
	return d
}

// ID is the device's ID.
func (d *Device) ID() DeviceID { return d.id }

// Account is the account ID: the hash of list entry 1.
func (d *Device) Account() Hash { return d.account }

// List is the device list as this device last checked it.
func (d *Device) List() *ListState { return d.list }

// Head is the newest list entry this device accepted.
func (d *Device) Head() uint32 { return d.head }

func hexID(id DeviceID) string { return hex.EncodeToString(id[:]) }

// Names on the server. They name devices and key IDs, which the server
// knows anyway (SS 4), never content.
const logList = "list"

func logWrites(id DeviceID) string    { return "w/" + hexID(id) }
func logSummaries(id DeviceID) string { return "s/" + hexID(id) }

// CreateAccount makes list entry 1 (this device and account key 1) and
// entry 2 (the first recovery kit). Sync starts only after ConfirmKit.
func (d *Device) CreateAccount() (*Kit, error) {
	if d.keys.Authority == nil {
		return nil, fmt.Errorf("%w: turn sync on from a device with Face ID or Touch ID (SS 6.1)", ErrNoAuthority)
	}
	g, err := newGen(1)
	if err != nil {
		return nil, err
	}
	en := &Entry{Num: 1, Body: Body{Action: ActCreate, Devices: []DeviceRecord{d.rec}, Key: &g.KeyGen}}
	js, err := joinSigs(d.keys, &d.rec, 0)
	if err != nil {
		return nil, err
	}
	en.Sigs = js
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return nil, err
	}
	d.joined = true
	if err := d.appendEntry(en); err != nil {
		return nil, err
	}
	d.account = d.list.Account
	d.installGen(g)
	kits, err := d.setKits(1, nil)
	if err != nil {
		return nil, err
	}
	if err := d.uploadGen(g); err != nil {
		return nil, err
	}
	d.kitToType = kits[0]
	return kits[0], nil
}

// ConfirmKit takes the two groups of the kit the person typed back. Sync
// starts only after this (spec 5.4).
func (d *Device) ConfirmKit(answers [2]string) error {
	if d.kitToType == nil {
		return nil
	}
	if !d.kitToType.CheckTyped(answers) {
		return ErrKitTypo
	}
	d.kitToType = nil
	return d.writeInfo()
}

// writeInfo writes this device's sealed name record, pinned by InfoHash.
func (d *Device) writeInfo() error {
	_, err := d.create(TypeDevice, idRecord(d.id), []Field{
		{Name: "device", Value: hexID(d.id)}, {Name: "name", Value: d.Name},
		{Name: "salt", Value: hex.EncodeToString(d.infoSalt)},
	})
	return err
}

// idRecord is the record ID of a device's name record. Only that device
// writes it (recordFits).
func idRecord(id DeviceID) RecordID {
	h := sum(labelInfo, id[:])
	return recordID(TypeDevice, [12]byte(h[:12]))
}

// DeviceName is a listed device's name from its sealed record, only when
// the record matches the hash in the signed list.
func (d *Device) DeviceName(id DeviceID) (string, bool) {
	f, ok := d.data.get(idRecord(id))
	rec, listed := d.list.Ever[id]
	if !ok || !listed {
		return "", false
	}
	salt, err := hex.DecodeString(f["salt"])
	if err != nil || len(salt) != infoSaltSize || deviceInfoHash(salt, f["name"]) != rec.InfoHash {
		return "", false
	}
	return f["name"], true
}

// nextEntry starts an entry after this device's head.
func (d *Device) nextEntry(b Body) *Entry {
	return &Entry{Num: d.head + 1, Prev: d.headHash, Body: b}
}

// appendEntry stores an entry only if no other device added one first,
// then checks the list again with it.
func (d *Device) appendEntry(en *Entry) error {
	// Check it as every other device will, before anyone can see it: a
	// bad entry on the server would stop every device.
	if en.Num > 1 {
		d.seen[en.Hash()] = d.now()
		entries := append(slices.Clip(d.list.Entries), en)
		if _, err := checkChain(entries, d.clockView(entries)); err != nil {
			return err
		}
	}
	err := d.srv.AppendAt(d.id, logList, int(en.Num-1), en.Marshal())
	if errors.Is(err, errConflict) {
		return ErrListConflict
	}
	if err != nil {
		return err
	}
	d.seen[en.Hash()] = d.now()
	return d.loadList(true)
}

// readList fetches and parses the list. Each entry's first-seen time is
// kept on this device: waits count from it (SS 6.2).
func readList(srv Server, by DeviceID, seen map[Hash]time.Time, now time.Time) ([]*Entry, error) {
	items, err := srv.Read(by, logList)
	if err != nil {
		return nil, err
	}
	entries := make([]*Entry, 0, len(items))
	for _, it := range items {
		en, err := ParseEntry(it)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrChainBroken, err)
		}
		h := en.Hash()
		if _, ok := seen[h]; !ok {
			seen[h] = now
		}
		entries = append(entries, en)
	}
	return entries, nil
}

func (d *Device) clockView(entries []*Entry) clockView {
	return clockView{now: d.now(), trustUpTo: d.trustUpTo, seen: func(num uint32) time.Time {
		if int(num) <= len(entries) {
			if t, ok := d.seen[entries[num-1].Hash()]; ok {
				return t
			}
		}
		return d.now()
	}}
}

// refreshList checks the whole list from entry 1 against what this device
// remembers: same account, never shorter, never split.
func (d *Device) refreshList() error { return d.loadList(false) }

// loadList is refreshList. own says the only new entry is the one this
// device just added: nothing to alert on or seal again for it.
func (d *Device) loadList(own bool) error {
	entries, err := readList(d.srv, d.id, d.seen, d.now())
	if err != nil {
		return err
	}
	st, err := checkChain(entries, d.clockView(entries))
	if err != nil {
		return err
	}
	if d.account != (Hash{}) && st.Account != d.account {
		return ErrAccountMismatch
	}
	if st.Head < d.head {
		return fmt.Errorf("%w: list has %d entries, this device saw %d", ErrRollback, st.Head, d.head)
	}
	if d.head > 0 && st.Hashes[d.head-1] != d.headHash {
		return fmt.Errorf("%w: list entry %d changed", ErrFork, d.head)
	}
	if d.joined && d.list != nil && !own {
		if st.Head > d.head && !d.alertDue {
			d.alertFrom, d.alertDue = d.head, true
		}
	}
	d.list, d.head, d.headHash = st, st.Head, st.HeadHash
	if d.joined && st.Members[d.id] == nil {
		if _, removed := st.Removed[d.id]; removed {
			return ErrRemoved
		}
	}
	return nil
}

// vaultID is the personal vault's ID.
func (d *Device) vaultID() [16]byte {
	var v [16]byte
	h := sum(labelVaultID, d.account[:])
	copy(v[:], h[:])
	return v
}

// tick makes the next clock stamp for a write.
func (d *Device) tick() HLC {
	wall := d.now().UnixMilli()
	if wall > d.hlc.Wall {
		d.hlc.Wall, d.hlc.Count = wall, 0
	} else {
		d.hlc.Count++
	}
	return d.hlc
}

// observe moves the clock past a stamp from another device.
func (d *Device) observe(c HLC) {
	if c.Wall > d.hlc.Wall || (c.Wall == d.hlc.Wall && c.Count > d.hlc.Count) {
		d.hlc.Wall, d.hlc.Count = c.Wall, c.Count
	}
}

// Get returns a record's agreed fields.
func (d *Device) Get(id RecordID) (map[string]string, bool) { return d.data.get(id) }

// Records counts the agreed, live records.
func (d *Device) Records() int { return d.data.count() }

// Waiting lists the changes that wait for a person's yes.
func (d *Device) Waiting() []Waiting { return d.data.list() }

// Unconfirmed lists the devices that have not yet signed a summary naming
// list entry num: a removal shows "not yet confirmed" for them (SS 7.1).
func (d *Device) Unconfirmed(num uint32) []DeviceID {
	var out []DeviceID
	for id := range d.list.Members {
		if s := d.summaries[id]; s == nil || s.ListNum < num {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b DeviceID) int { return slices.Compare(a[:], b[:]) })
	return out
}

// DroppableMarkers lists deletion markers every current device has
// covered with a signed summary, so they may be dropped (SS 9).
func (d *Device) DroppableMarkers() []RecordID {
	var out []RecordID
	for rid, ref := range d.data.markers {
		ok := true
		for id := range d.list.Members {
			s := d.summaries[id]
			if s == nil || headOf(s, ref.Writer).Seq < ref.Seq {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, rid)
		}
	}
	return out
}

func headOf(s *Summary, dev DeviceID) Head {
	for _, h := range s.Heads {
		if h.Device == dev {
			return h
		}
	}
	return Head{}
}

// baseData is a fresh merge state to merge every write again on: the
// state of the snapshot this device builds on, or empty.
func (d *Device) baseData() *mergeState {
	if d.base == nil {
		return newMergeState()
	}
	return d.base.clone()
}
