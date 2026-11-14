package syncproto

import (
	"bytes"
	"fmt"
	"time"
)

type member struct {
	Rec DeviceRecord
	// AddedAt is the entry that added the device, or that last replaced
	// its authority key (which counts as a device added that day, SS 6.1).
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
	Requester []byte   // the authority key that may apply it
	ReqDevice DeviceID // the device asking (for a takeover: the new device)
	Wait      time.Duration
	Done      bool
	Cancelled bool
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
	Ever     map[DeviceID]DeviceRecord
	FirstAt  map[DeviceID]uint32
	Auth     map[DeviceID][]authSpan
	Gen      KeyGen
	Gens     map[uint32]KeyGen
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
var shapes = map[Action][2]int{
	ActCreate:           {fDevices | fKey, fDevices | fKey},
	ActSetKits:          {fKits, fKits | fKey},
	ActAddDevice:        {fDevices, fDevices},
	ActRemove:           {fRemoves | fKey, fRemoves | fKey},
	ActReplaceAuthority: {fAuth, fAuth},
	ActRecoveryStep:     {fKey | fKits, fKey | fKits | fRemoves},
	ActTakeover:         {fDevices | fRemoves | fKey | fKits, fDevices | fRemoves | fKey | fKits},
	ActPending:          {fInner, fInner},
	ActApply:            {fRef, fRef | fRemoves},
	ActCancel:           {fRef, fRef},
}

// checkShape refuses a body with a field its action does not use, a
// missing field, or an action in the wrong place.
func checkShape(b *Body, inner bool) error {
	s, ok := shapes[b.Action]
	if !ok {
		return fmt.Errorf("%w: unknown action", ErrChainBroken)
	}
	f := usedFields(b)
	if f&s[0] != s[0] || f&^s[1] != 0 {
		return fmt.Errorf("%w: fields do not fit the action", ErrChainBroken)
	}
	waits := b.Action == ActTakeover || b.Action == ActSetKits || b.Action == ActRemove
	if (inner && !waits) || (!inner && b.Action == ActTakeover) {
		return fmt.Errorf("%w: action not allowed here", ErrChainBroken)
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
		_, ok := st.authSigner(en)
		if !ok || !newKitsSigned(en, b) || (len(st.Kits) > 0 && !st.kitSigned(en)) {
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
		if !st.kitSigned(en) && st.youngRemovesOlder(signer, b.Removes, en.Num, cv) {
			return nil, ErrYoungDevice
		}
		return nil, st.applyRemoval(b.Removes, b.Key, &signer)
	case ActReplaceAuthority:
		return nil, st.applyReplaceAuth(en, b)
	case ActRecoveryStep:
		if !st.kitSigned(en) || !newKitsSigned(en, b) {
			return nil, ErrNotAuthorized
		}
		if err := st.applyRemoval(b.Removes, b.Key, nil); err != nil {
			return nil, err
		}
		st.Kits = b.Kits
	case ActPending:
		return nil, st.applyPending(en)
	case ActApply:
		return st.applyApply(en, cv)
	case ActCancel:
		p := st.Pending[b.Ref]
		if p == nil || p.Done {
			return nil, fmt.Errorf("%w: nothing waiting at entry %d", ErrChainBroken, b.Ref)
		}
		if _, ok := st.authSigner(en); !ok && !st.kitSigned(en) {
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

func (st *ListState) applyReplaceAuth(en *Entry, b *Body) error {
	m := st.Members[b.AuthOf]
	if m == nil || parsePub(b.NewAuth) == nil {
		return ErrNotAuthorized
	}
	signer, ok := st.authSigner(en)
	if (!ok || signer == b.AuthOf) && !st.kitSigned(en) {
		return fmt.Errorf("%w: a new authority key is signed in by another device or the kit", ErrNotAuthorized)
	}
	st.closeAuth(b.AuthOf, en.Num)
	m.Rec.AuthPub = append([]byte{}, b.NewAuth...)
	m.AddedAt = en.Num
	st.Auth[b.AuthOf] = append(st.Auth[b.AuthOf], authSpan{Pub: m.Rec.AuthPub, From: en.Num})
	return nil
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
		p.Requester, p.ReqDevice, p.Wait = rec.AuthPub, rec.ID(), WaitRecovery
	case ActSetKits, ActRemove:
		signer, ok := st.authSigner(en)
		if !ok || (in.Action == ActSetKits && !newKitsSigned(en, in)) {
			return ErrNotAuthorized
		}
		p.Requester, p.ReqDevice = st.Members[signer].Rec.AuthPub, signer
		p.Wait = WaitKitLost
		if in.Action == ActRemove {
			p.Wait = WaitYoung
		}
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
		if err := st.applyRemoval(removes, in.Key, nil); err != nil {
			return nil, err
		}
		st.Kits = in.Kits
	case ActSetKits:
		if err := st.applyKits(in); err != nil {
			return nil, err
		}
	case ActRemove:
		if err := st.applyRemoval(in.Removes, in.Key, &p.ReqDevice); err != nil {
			return nil, err
		}
	}
	p.Done = true
	return nil, nil
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
	st.Kits = b.Kits
	return nil
}

// applyRemoval removes devices and starts the next key generation.
func (st *ListState) applyRemoval(rs []Removal, key *KeyGen, signer *DeviceID) error {
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
	st.setGen(*key)
	return nil
}

// youngRemovesOlder is the 7-day rule (SS 6.2), on this device's clock:
// the gap between first seeing the signer's entry and first seeing this
// one.
func (st *ListState) youngRemovesOlder(signer DeviceID, rs []Removal, at uint32, cv clockView) bool {
	s := st.Members[signer]
	if s.AddedAt <= cv.trustUpTo || at <= cv.trustUpTo {
		return false
	}
	if cv.seen(at).Sub(cv.seen(s.AddedAt)) >= WaitYoung {
		return false
	}
	for _, r := range rs {
		if t := st.Members[r.Device]; t != nil && r.Device != signer && t.AddedAt < s.AddedAt {
			return true
		}
	}
	return false
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
func (st *ListState) kitSigned(en *Entry) bool {
	msg := en.signedBytes()
	for _, s := range en.Sigs {
		if s.Role == RoleKit && int(s.Index) < len(st.Kits) &&
			verifySig(parsePub(st.Kits[s.Index].SignPub), labelEntry, msg, s.Sig) {
			return true
		}
	}
	return false
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
