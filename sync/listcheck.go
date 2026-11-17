package komandosync

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"time"
)

type member struct {
	Rec DeviceRecord
	// AddedAt is the entry that added the device, or that last replaced
	// its authority key (which counts as a device added that day, SS 6.1).
	// It limits what the device may do; how old it is to others is
	// ListState.FirstAt.
	AddedAt uint32
}

// authSpan is an authority key and the entries it was valid for (To 0:
// still valid). Approvals are checked against the key valid when made.
type authSpan struct {
	Pub      []byte
	From, To uint32
}

type pendingChange struct {
	Num       uint32
	Inner     Body
	Requester []byte   // the key that may apply it: an authority key, or a sync key for a kit step on a device
	ReqDevice DeviceID // the device asking (for a takeover: the new device)
	Wait      time.Duration
	Kit       bool   // the recovery key signed it (SS 6.4)
	KitPub    []byte // the signing key of the kit that signed it
	OldAuth   []byte // a new authority key: the key it replaces
	Done      bool
	Cancelled bool
	KitGone   bool // the kit that signed it was replaced first: it never applies
}

// removalInfo is where a device was removed and which devices stayed.
// Their signed summaries from before that entry decide which of its writes
// count (SS 6.2).
type removalInfo struct {
	At        uint32
	Remaining []DeviceID
}

// Hold says the list stops before Entry until this device's own clock
// passes Until. Nothing is refused; it waits.
type Hold struct {
	Entry  uint32
	Until  time.Time
	Reason string
}

// ListState is the device list as one device checked it from entry 1.
type ListState struct {
	Account  Hash
	Head     uint32
	HeadHash Hash
	Members  map[DeviceID]*member
	Removed  map[DeviceID]Removal
	RemInfo  map[DeviceID]removalInfo
	Ever     map[DeviceID]DeviceRecord
	FirstAt  map[DeviceID]uint32
	Auth     map[DeviceID][]authSpan
	Gen      KeyGen
	Gens     map[uint32]KeyGen
	GenAt    []uint32 // GenAt[n-1]: the generation in force after entry n
	Kits     []KitRecord
	Pending  map[uint32]*pendingChange
	Hold     *Hold
	Hashes   []Hash
	Entries  []*Entry
}

// clockView is what the checking device knows about time. Entries up to
// trustUpTo came before the device remembered anything (a new device
// takes them as vouched for by the device that paired it); time rules
// apply only after that.
type clockView struct {
	now       time.Time
	seen      func(num uint32) time.Time
	trustUpTo uint32
}

func newListState() *ListState {
	return &ListState{
		Members: map[DeviceID]*member{},
		Removed: map[DeviceID]Removal{},
		RemInfo: map[DeviceID]removalInfo{},
		Ever:    map[DeviceID]DeviceRecord{},
		FirstAt: map[DeviceID]uint32{},
		Auth:    map[DeviceID][]authSpan{},
		Gens:    map[uint32]KeyGen{},
		Pending: map[uint32]*pendingChange{},
	}
}

// checkChain checks the whole list from entry 1. It stops early, without
// an error, at an entry that waits on this device's clock (st.Hold).
func checkChain(entries []*Entry, cv clockView) (*ListState, error) {
	st := newListState()
	if len(entries) == 0 {
		return nil, ErrChainBroken
	}
	for i, en := range entries {
		if en.Num != uint32(i+1) {
			return nil, fmt.Errorf("%w: entry %d is at place %d", ErrChainBroken, en.Num, i+1)
		}
		var prev Hash
		if i > 0 {
			prev = st.Hashes[i-1]
		}
		if en.Prev != prev {
			return nil, fmt.Errorf("%w: entry %d", ErrChainBroken, en.Num)
		}
		if err := checkShape(&en.Body, false); err != nil {
			return nil, fmt.Errorf("entry %d: %w", en.Num, err)
		}
		var hold *Hold
		var err error
		if i == 0 {
			err = st.applyCreate(en)
		} else {
			hold, err = st.apply(en, cv)
		}
		if err != nil {
			return nil, fmt.Errorf("entry %d (%s): %w", en.Num, en.Body.Action, err)
		}
		if hold != nil {
			st.Hold = hold
			break
		}
		h := en.Hash()
		st.Hashes = append(st.Hashes, h)
		st.Entries = append(st.Entries, en)
		st.GenAt = append(st.GenAt, st.Gen.Gen)
		st.Head, st.HeadHash = en.Num, h
	}
	return st, nil
}

// The fields of a body, as bits, for checkShape.
const (
	fDevices = 1 << iota
	fRemoves
	fKey
	fKits
	fAuth
	fRef
	fInner
)

func usedFields(b *Body) int {
	var f int
	if len(b.Devices) > 0 {
		f |= fDevices
	}
	if len(b.Removes) > 0 {
		f |= fRemoves
	}
	if b.Key != nil {
		f |= fKey
	}
	if len(b.Kits) > 0 {
		f |= fKits
	}
	if b.AuthOf != (DeviceID{}) || len(b.NewAuth) > 0 {
		f |= fAuth
	}
	if b.Ref != 0 {
		f |= fRef
	}
	if b.Inner != nil {
		f |= fInner
	}
	return f
}

// shapes: for each action, the fields it needs and the fields it may have.
// A pending change holds only its intent; its apply carries the new key,
// made when it applies, so a key change during the wait never strands it.
var shapes = map[Action][2]int{
	ActCreate:           {fDevices | fKey, fDevices | fKey},
	ActSetKits:          {fKits, fKits | fKey},
	ActAddDevice:        {fDevices, fDevices},
	ActRemove:           {fRemoves | fKey, fRemoves | fKey},
	ActReplaceAuthority: {fAuth, fAuth},
	ActRecoveryStep:     {fKey | fKits, fKey | fKits | fRemoves},
	ActPending:          {fInner, fInner},
	ActApply:            {fRef, fRef | fRemoves | fKey},
	ActCancel:           {fRef, fRef},
}

// innerShapes are the changes a Pending entry may hold.
var innerShapes = map[Action][2]int{
	ActTakeover:         {fDevices | fRemoves | fKits, fDevices | fRemoves | fKits},
	ActSetKits:          {fKits, fKits},
	ActRemove:           {fRemoves, fRemoves},
	ActRecoveryStep:     {fKits, fKits | fRemoves},
	ActReplaceAuthority: {fAuth, fAuth},
}

// checkShape refuses a body with a field its action does not use, a
// missing field, or an action in the wrong place.
func checkShape(b *Body, inner bool) error {
	table := shapes
	if inner {
		table = innerShapes
	}
	s, ok := table[b.Action]
	if !ok {
		return fmt.Errorf("%w: unknown action or action not allowed here", ErrChainBroken)
	}
	f := usedFields(b)
	if f&s[0] != s[0] || f&^s[1] != 0 {
		return fmt.Errorf("%w: fields do not fit the action", ErrChainBroken)
	}
	if b.Action == ActPending {
		return checkShape(b.Inner, true)
	}
	if len(b.Devices) > 1 || len(b.Kits) > MaxKits {
		return fmt.Errorf("%w: too many devices or kits", ErrChainBroken)
	}
	for i := range b.Devices {
		if !b.Devices[i].valid() {
			return fmt.Errorf("%w: device keys do not parse", ErrChainBroken)
		}
	}
	return nil
}

func (st *ListState) applyCreate(en *Entry) error {
	b := &en.Body
	if b.Action != ActCreate || len(b.Devices) != 1 || b.Key.Gen != 1 {
		return ErrChainBroken
	}
	rec := b.Devices[0]
	if len(rec.AuthPub) == 0 {
		return fmt.Errorf("%w: the first device needs an authority key", ErrNotAuthorized)
	}
	if !joinSigned(en, b) || !st.sigBy(en, RoleAuthority, rec.ID(), rec.AuthPub) {
		return ErrNotAuthorized
	}
	st.Account = en.Hash()
	st.addMember(rec, en.Num)
	st.setGen(*b.Key)
	return nil
}

func (st *ListState) apply(en *Entry, cv clockView) (*Hold, error) {
	b := &en.Body
	switch b.Action {
	case ActSetKits:
		// Replacing kits needs a current kit's signature: the recovery key
		// typed (SS 6.4). Without it, only as a pending change (lost kit).
		// A kit step applies at once only when no other device is listed;
		// otherwise it is a pending change of 24 hours.
		signer, ok := st.authSigner(en)
		if !ok || !newKitsSigned(en, b) || (len(st.Kits) > 0 && (!st.kitSigned(en) || !st.alone(signer))) {
			return nil, ErrNotAuthorized
		}
		return nil, st.applyKits(b)
	case ActAddDevice:
		return nil, st.applyAdd(en, b)
	case ActRemove:
		signer, ok := st.authSigner(en)
		if !ok {
			return nil, ErrNotAuthorized
		}
		if h := st.youngHold(signer, removed(b.Removes), en.Num, cv); h != nil {
			return h, nil
		}
		return nil, st.applyRemoval(b.Removes, b.Key)
	case ActReplaceAuthority:
		return st.applyReplaceAuth(en, b, cv)
	case ActRecoveryStep:
		// The kit is used on a device already on the list (SS 6.4): that
		// device's sync key signs too, and it does not remove itself. A kit
		// alone, on a device that is not listed, only gets the 24-hour
		// takeover. At once only when no other device is listed; otherwise
		// it is a pending change of 24 hours.
		dev, ok := st.recoveryStepBy(en, b)
		if !ok || !st.alone(dev) {
			return nil, ErrNotAuthorized
		}
		if err := st.applyRemoval(b.Removes, b.Key); err != nil {
			return nil, err
		}
		st.setKits(b.Kits)
	case ActPending:
		return nil, st.applyPending(en)
	case ActApply:
		return st.applyApply(en, cv)
	case ActCancel:
		p := st.Pending[b.Ref]
		if p == nil || p.Done {
			return nil, fmt.Errorf("%w: nothing waiting at entry %d", ErrChainBroken, b.Ref)
		}
		// Only a listed authority key cancels (SS 6.4: "any device"). Never
		// a kit: the kit a lost-kit replacement ends must not block it.
		if _, ok := st.authSigner(en); !ok {
			return nil, ErrNotAuthorized
		}
		p.Done, p.Cancelled = true, true
	default:
		return nil, ErrChainBroken
	}
	return nil, nil
}

func (st *ListState) applyAdd(en *Entry, b *Body) error {
	if _, ok := st.authSigner(en); !ok || !joinSigned(en, b) {
		return ErrNotAuthorized
	}
	rec := b.Devices[0]
	if _, seen := st.Ever[rec.ID()]; seen {
		return fmt.Errorf("%w: a device ID is never listed twice", ErrNotAuthorized)
	}
	st.addMember(rec, en.Num)
	return nil
}

// applyReplaceAuth signs in a device's new authority key (SS 6.1). The
// device itself asks, with its sync key, and the new key proves itself.
// Another listed authority key signs it in; a signer listed less than 7
// days ago does so for an older device only after its wait. The recovery
// key signs it in at once only when the device is the only one listed;
// otherwise as a pending change of 24 hours.
func (st *ListState) applyReplaceAuth(en *Entry, b *Body, cv clockView) (*Hold, error) {
	if err := st.authAsked(en, b); err != nil {
		return nil, err
	}
	signer, ok := st.authSigner(en)
	switch {
	case ok && signer != b.AuthOf:
		if h := st.youngHold(signer, []DeviceID{b.AuthOf}, en.Num, cv); h != nil {
			return h, nil
		}
	case st.kitSigned(en) && st.alone(b.AuthOf):
	default:
		return nil, fmt.Errorf("%w: a new authority key is signed in by another device, or by the kit after 24 hours", ErrNotAuthorized)
	}
	st.setAuth(b.AuthOf, b.NewAuth, en.Num)
	return nil, nil
}

// authAsked checks the device's own request for a new authority key: its
// sync key asks, the new key proves itself, and both name the key it
// replaces.
func (st *ListState) authAsked(en *Entry, b *Body) error {
	m := st.Members[b.AuthOf]
	if m == nil || parsePub(b.NewAuth) == nil {
		return ErrNotAuthorized
	}
	msg := authAskBytes(st.Account, b.AuthOf, m.Rec.AuthPub, b.NewAuth)
	if !sigOver(en, RoleAuthAsk, b.AuthOf, m.Rec.SyncPub, msg) || !sigOver(en, RoleAuthProof, b.AuthOf, b.NewAuth, msg) {
		return fmt.Errorf("%w: the device itself asks for a new authority key", ErrNotAuthorized)
	}
	return nil
}

func (st *ListState) setAuth(dev DeviceID, pub []byte, at uint32) {
	m := st.Members[dev]
	st.closeAuth(dev, at)
	m.Rec.AuthPub = append([]byte{}, pub...)
	m.AddedAt = at
	st.Auth[dev] = append(st.Auth[dev], authSpan{Pub: m.Rec.AuthPub, From: at})
}

// recoveryStepBy checks a recovery step's signatures: a current kit, the
// new kits, and the sync key of the listed device it is used on, which
// does not remove itself.
func (st *ListState) recoveryStepBy(en *Entry, b *Body) (DeviceID, bool) {
	dev, ok := st.syncSigner(en)
	if !ok || !st.kitSigned(en) || !newKitsSigned(en, b) || slices.Contains(removed(b.Removes), dev) {
		return DeviceID{}, false
	}
	return dev, true
}

// alone reports whether dev is the only listed device. Only then does a
// recovery-key step apply at once (SS 6.4).
func (st *ListState) alone(dev DeviceID) bool {
	return len(st.Members) == 1 && st.Members[dev] != nil
}

func (st *ListState) applyPending(en *Entry) error {
	in := en.Body.Inner
	p := &pendingChange{Num: en.Num, Inner: *in}
	switch in.Action {
	case ActTakeover:
		rec := in.Devices[0]
		if len(rec.AuthPub) == 0 || !st.kitSigned(en) || !joinSigned(en, in) || !newKitsSigned(en, in) {
			return ErrNotAuthorized
		}
		if _, seen := st.Ever[rec.ID()]; seen {
			return ErrNotAuthorized
		}
		p.Requester, p.ReqDevice, p.Wait, p.Kit = rec.AuthPub, rec.ID(), WaitRecovery, true
	case ActSetKits, ActRemove:
		signer, ok := st.authSigner(en)
		if !ok || (in.Action == ActSetKits && !newKitsSigned(en, in)) {
			return ErrNotAuthorized
		}
		p.Requester, p.ReqDevice = st.Members[signer].Rec.AuthPub, signer
		switch {
		case in.Action == ActRemove:
			p.Wait = WaitYoung
		case st.kitSigned(en): // the recovery key typed: 24 hours
			p.Wait, p.Kit = WaitRecovery, true
		default: // a lost kit: 7 days
			p.Wait = WaitKitLost
		}
	case ActRecoveryStep:
		dev, ok := st.recoveryStepBy(en, in)
		if !ok {
			return ErrNotAuthorized
		}
		p.Requester, p.ReqDevice, p.Wait, p.Kit = st.Members[dev].Rec.SyncPub, dev, WaitRecovery, true
	case ActReplaceAuthority:
		if err := st.authAsked(en, in); err != nil {
			return err
		}
		m := st.Members[in.AuthOf]
		p.OldAuth = m.Rec.AuthPub
		if signer, ok := st.authSigner(en); ok && signer != in.AuthOf {
			// A young signer's sign-in for an older device (SS 6.1).
			p.Requester, p.ReqDevice, p.Wait = st.Members[signer].Rec.AuthPub, signer, WaitYoung
		} else if st.kitSigned(en) {
			// The kit signs; the device that asked applies it with its sync
			// key: its new authority key signs nothing until then.
			p.Requester, p.ReqDevice, p.Wait, p.Kit = m.Rec.SyncPub, in.AuthOf, WaitRecovery, true
		} else {
			return ErrNotAuthorized
		}
	}
	if p.Kit {
		p.KitPub = st.kitSigner(en)
	}
	st.Pending[en.Num] = p
	return nil
}

func (st *ListState) applyApply(en *Entry, cv clockView) (*Hold, error) {
	b := &en.Body
	p := st.Pending[b.Ref]
	if p == nil || p.Done {
		return nil, fmt.Errorf("%w: nothing waiting at entry %d", ErrChainBroken, b.Ref)
	}
	if p.Inner.Action != ActTakeover && st.Members[p.ReqDevice] == nil {
		return nil, fmt.Errorf("%w: the asking device was removed", ErrNotAuthorized)
	}
	if !st.sigBy(en, RoleRequester, p.ReqDevice, p.Requester) {
		return nil, ErrNotAuthorized
	}
	if p.Num > cv.trustUpTo {
		if until := cv.seen(p.Num).Add(p.Wait); cv.now.Before(until) {
			return &Hold{Entry: en.Num, Until: until, Reason: "a waiting " + p.Inner.Action.String() +
				" was applied before this device saw it wait its full time"}, nil
		}
	}
	in := &p.Inner
	if len(b.Removes) > 0 && in.Action != ActTakeover {
		return nil, fmt.Errorf("%w: only a takeover's apply names removals", ErrChainBroken)
	}
	p.Done = true // before its own kits replace the kit that signed it
	switch in.Action {
	case ActTakeover:
		removes := in.Removes
		if len(b.Removes) > 0 {
			removes = b.Removes
		}
		if len(removes) != len(st.Members) {
			return nil, fmt.Errorf("%w: a takeover removes every other device", ErrNotAuthorized)
		}
		rec := in.Devices[0]
		st.addMember(rec, en.Num)
		if err := st.applyRemoval(removes, b.Key); err != nil {
			return nil, err
		}
		st.setKits(in.Kits)
	case ActRecoveryStep:
		if err := st.applyRemoval(st.stillListed(in.Removes), b.Key); err != nil {
			return nil, err
		}
		st.setKits(in.Kits)
	case ActReplaceAuthority:
		if b.Key != nil {
			return nil, fmt.Errorf("%w: a new authority key starts no key generation", ErrChainBroken)
		}
		// A key changed again during the wait: the request is stale and
		// applies as done.
		if m := st.Members[in.AuthOf]; m != nil && bytes.Equal(m.Rec.AuthPub, p.OldAuth) {
			st.setAuth(in.AuthOf, in.NewAuth, en.Num)
		}
	case ActSetKits:
		kb := *in
		kb.Key = b.Key
		if err := st.applyKits(&kb); err != nil {
			return nil, err
		}
	case ActRemove:
		// A device another entry removed during the wait is gone already.
		rs := st.stillListed(in.Removes)
		if len(rs) == 0 {
			if b.Key != nil {
				return nil, fmt.Errorf("%w: nothing left to remove", ErrChainBroken)
			}
			break
		}
		if err := st.applyRemoval(rs, b.Key); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// stillListed keeps the removals of devices that are still listed.
func (st *ListState) stillListed(rs []Removal) []Removal {
	var out []Removal
	for _, r := range rs {
		if st.Members[r.Device] != nil {
			out = append(out, r)
		}
	}
	return out
}

// applyKits sets the kit set. Replacing kits starts a new account key
// generation: the old kits hold sealed copies of the current key on the
// server, so without one an old kit would still open everything.
func (st *ListState) applyKits(b *Body) error {
	if len(st.Kits) > 0 {
		if b.Key == nil || b.Key.Gen != st.Gen.Gen+1 {
			return fmt.Errorf("%w: replacing kits starts the next key generation", ErrChainBroken)
		}
		st.setGen(*b.Key)
	} else if b.Key != nil {
		return fmt.Errorf("%w: the first kits keep the key", ErrChainBroken)
	}
	st.setKits(b.Kits)
	return nil
}

// setKits replaces the kit set. Every waiting step a replaced kit signed
// ends with it (SS 6.4: replacing the kits ends the old kit, and its
// waiting steps too). Otherwise a thief who started two steps with a kit
// would still hold one after the person replaced the kits.
func (st *ListState) setKits(kits []KitRecord) {
	st.Kits = kits
	for _, p := range st.Pending {
		if p.Done || !p.Kit || slices.ContainsFunc(kits, func(k KitRecord) bool { return bytes.Equal(k.SignPub, p.KitPub) }) {
			continue
		}
		p.Done, p.KitGone = true, true
	}
}

// applyRemoval removes devices and starts the next key generation.
func (st *ListState) applyRemoval(rs []Removal, key *KeyGen) error {
	if key == nil || key.Gen != st.Gen.Gen+1 {
		return fmt.Errorf("%w: a removal starts the next key generation", ErrChainBroken)
	}
	seen := map[DeviceID]bool{}
	for _, r := range rs {
		if st.Members[r.Device] == nil || seen[r.Device] {
			return fmt.Errorf("%w: removes a device that is not listed", ErrChainBroken)
		}
		seen[r.Device] = true
	}
	if len(seen) >= len(st.Members) {
		return fmt.Errorf("%w: a removal leaves at least one device", ErrChainBroken)
	}
	for _, r := range rs {
		delete(st.Members, r.Device)
		st.Removed[r.Device] = r
		st.closeAuth(r.Device, st.Head+1)
	}
	remaining := slices.SortedFunc(maps.Keys(st.Members), func(a, b DeviceID) int { return bytes.Compare(a[:], b[:]) })
	for _, r := range rs {
		st.RemInfo[r.Device] = removalInfo{At: st.Head + 1, Remaining: remaining}
	}
	st.setGen(*key)
	return nil
}

// youngHold is the 7-day rule (SS 6.2), on this device's clock. A signer
// first seen (its addition, or its newest authority key) less than 7 days
// ago that acts on an older device holds the list at this entry until 7
// days have passed: time only delays, never refuses. A target is older
// when it was first listed before the signer's entry; a new authority key
// never makes its device younger in the eyes of others.
func (st *ListState) youngHold(signer DeviceID, targets []DeviceID, at uint32, cv clockView) *Hold {
	s := st.Members[signer]
	if s.AddedAt <= cv.trustUpTo || at <= cv.trustUpTo {
		return nil
	}
	until := cv.seen(s.AddedAt).Add(WaitYoung)
	if !cv.now.Before(until) {
		return nil
	}
	for _, t := range targets {
		if st.Members[t] != nil && t != signer && st.FirstAt[t] < s.AddedAt {
			return &Hold{Entry: at, Until: until, Reason: "a device listed less than 7 days ago acted on an older device without waiting"}
		}
	}
	return nil
}

func removed(rs []Removal) []DeviceID {
	out := make([]DeviceID, len(rs))
	for i, r := range rs {
		out[i] = r.Device
	}
	return out
}

func (st *ListState) addMember(rec DeviceRecord, at uint32) {
	id := rec.ID()
	st.Members[id] = &member{Rec: rec, AddedAt: at}
	st.Ever[id] = rec
	st.FirstAt[id] = at
	if len(rec.AuthPub) > 0 {
		st.Auth[id] = append(st.Auth[id], authSpan{Pub: rec.AuthPub, From: at})
	}
}

func (st *ListState) closeAuth(id DeviceID, at uint32) {
	spans := st.Auth[id]
	if n := len(spans); n > 0 && spans[n-1].To == 0 {
		spans[n-1].To = at
	}
}

func (st *ListState) setGen(k KeyGen) {
	st.Gen = k
	st.Gens[k.Gen] = k
}

// authSigner finds a listed device whose authority key signed the entry.
func (st *ListState) authSigner(en *Entry) (DeviceID, bool) {
	for _, s := range en.Sigs {
		m := st.Members[s.Device]
		if s.Role == RoleAuthority && m != nil && st.sigBy(en, RoleAuthority, s.Device, m.Rec.AuthPub) {
			return s.Device, true
		}
	}
	return DeviceID{}, false
}

// syncSigner finds a listed device whose sync key signed the entry.
func (st *ListState) syncSigner(en *Entry) (DeviceID, bool) {
	for _, s := range en.Sigs {
		m := st.Members[s.Device]
		if s.Role == RoleDevice && m != nil && st.sigBy(en, RoleDevice, s.Device, m.Rec.SyncPub) {
			return s.Device, true
		}
	}
	return DeviceID{}, false
}

// sigOver reports whether pub, in the given role for dev, signed msg (not
// the entry) under labelAuthAsk.
func sigOver(en *Entry, role SigRole, dev DeviceID, pub, msg []byte) bool {
	k := parsePub(pub)
	if k == nil {
		return false
	}
	for _, s := range en.Sigs {
		if s.Role == role && s.Device == dev && verifySig(k, labelAuthAsk, msg, s.Sig) {
			return true
		}
	}
	return false
}

// sigBy reports whether pub, in the given role for dev, signed the entry.
func (st *ListState) sigBy(en *Entry, role SigRole, dev DeviceID, pub []byte) bool {
	k := parsePub(pub)
	if k == nil {
		return false
	}
	msg := en.signedBytes()
	for _, s := range en.Sigs {
		if s.Role == role && s.Device == dev && verifySig(k, labelEntry, msg, s.Sig) {
			return true
		}
	}
	return false
}

// kitSigned reports whether a current recovery kit signed the entry.
func (st *ListState) kitSigned(en *Entry) bool { return st.kitSigner(en) != nil }

// kitSigner is the signing key of the current kit that signed the entry,
// or nil.
func (st *ListState) kitSigner(en *Entry) []byte {
	msg := en.signedBytes()
	for _, s := range en.Sigs {
		if s.Role == RoleKit && int(s.Index) < len(st.Kits) &&
			verifySig(parsePub(st.Kits[s.Index].SignPub), labelEntry, msg, s.Sig) {
			return st.Kits[s.Index].SignPub
		}
	}
	return nil
}

// joinSigned checks the new device's proofs for b.Devices[0].
func joinSigned(en *Entry, b *Body) bool {
	rec := b.Devices[0]
	id, msg := rec.ID(), rec.bytes()
	ok := func(role SigRole, pub []byte) bool {
		for _, s := range en.Sigs {
			if s.Role == role && s.Device == id && verifySig(parsePub(pub), labelJoin, msg, s.Sig) {
				return true
			}
		}
		return false
	}
	return ok(RoleJoinSync, rec.SyncPub) && (len(rec.AuthPub) == 0 || ok(RoleJoinAuth, rec.AuthPub))
}

// newKitsSigned checks every new kit signed itself into this place.
func newKitsSigned(en *Entry, b *Body) bool {
	for i, k := range b.Kits {
		found := false
		for _, s := range en.Sigs {
			if s.Role == RoleNewKit && int(s.Index) == i && verifyNewKitSig(k, en.Prev, s.Sig) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// authKeyAt is the authority key dev had at list entry num, or nil.
func (st *ListState) authKeyAt(dev DeviceID, num uint32) []byte {
	for _, s := range st.Auth[dev] {
		if num >= s.From && (s.To == 0 || num < s.To) {
			return s.Pub
		}
	}
	return nil
}

// kitIndex finds a kit among the current kits.
func (st *ListState) kitIndex(r KitRecord) int {
	for i, k := range st.Kits {
		if bytes.Equal(k.SignPub, r.SignPub) && bytes.Equal(k.SealPub, r.SealPub) {
			return i
		}
	}
	return -1
}
