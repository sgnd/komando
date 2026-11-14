package komandosync

import "bytes"

// The format and suite numbers. One suite number names the whole set of
// algorithms; there is no other (SS 7.2).
const (
	formatVersion uint8  = 1
	suite1        uint16 = 1
	minClient     uint32 = 1
)

// HLC is a hybrid clock: wall time in milliseconds, a counter, and the
// device that made it, so two stamps are never equal (SS 9).
type HLC struct {
	Wall  int64
	Count uint32
	Dev   DeviceID
}

// Less orders stamps by time, counter, device.
func (a HLC) Less(b HLC) bool {
	if a.Wall != b.Wall {
		return a.Wall < b.Wall
	}
	if a.Count != b.Count {
		return a.Count < b.Count
	}
	return bytes.Compare(a.Dev[:], b.Dev[:]) < 0
}

// WriteRef names one write of one device.
type WriteRef struct {
	Writer DeviceID
	Seq    uint64
	Hash   Hash
}

// Write is one signed, sealed change. The header is in the clear and
// bound to the sealed body; record ID, type, field names and values are
// only inside the body.
type Write struct {
	Account  Hash
	Vault    [16]byte
	Writer   DeviceID
	Seq      uint64
	Prev     Hash // hash of the writer's previous write; zero for write 1
	ListNum  uint32
	ListHash Hash // the newest list entry the writer knew
	KeyGen   uint32
	Clock    HLC
	Body     sealed
	Sig      Sig
}

// header is the place every write is bound to (SS 7.2): format, suite,
// account, vault, writer, its running number, the chain, the list entry,
// the key generation and the clock.
func (w *Write) header() []byte {
	var e enc
	e.u8(formatVersion)
	e.u16(suite1)
	e.raw(w.Account[:])
	e.raw(w.Vault[:])
	e.raw(w.Writer[:])
	e.u64(w.Seq)
	e.raw(w.Prev[:])
	e.u32(w.ListNum)
	e.raw(w.ListHash[:])
	e.u32(w.KeyGen)
	e.u64(uint64(w.Clock.Wall))
	e.u32(w.Clock.Count)
	return e.b
}

func (w *Write) signedBytes() []byte {
	return append(w.header(), w.Body.bytes()...)
}

// Hash covers the signed content, never the signature.
func (w *Write) Hash() Hash { return sum(labelWriteHash, w.signedBytes()) }

// Ref names the write.
func (w *Write) Ref() WriteRef { return WriteRef{w.Writer, w.Seq, w.Hash()} }

// Marshal is the write as stored on the server.
func (w *Write) Marshal() []byte { return append(w.signedBytes(), w.Sig[:]...) }

// ParseWrite reads a stored write.
func ParseWrite(b []byte) (*Write, error) {
	d := dec{b: b}
	if d.u8() != formatVersion || d.u16() != suite1 {
		return nil, ErrBadWrite
	}
	w := &Write{}
	d.fixed(w.Account[:])
	d.fixed(w.Vault[:])
	d.fixed(w.Writer[:])
	w.Seq = d.u64()
	d.fixed(w.Prev[:])
	w.ListNum = d.u32()
	d.fixed(w.ListHash[:])
	w.KeyGen = d.u32()
	w.Clock = HLC{Wall: int64(d.u64()), Count: d.u32(), Dev: w.Writer}
	w.Body = decodeSealed(&d)
	d.fixed(w.Sig[:])
	if err := d.done(); err != nil {
		return nil, err
	}
	return w, nil
}

// Field is one field of a record.
type Field struct {
	Name, Value string
}

// The kinds of change a sealed body holds.
const (
	kindRecord   uint8 = 1
	kindApproval uint8 = 2
	kindReseal   uint8 = 3 // an own record change sealed again under a newer key generation (Target names it)
)

// Change is the opened body of a write.
type Change struct {
	Kind   uint8
	Record RecordID
	Type   string
	Create bool
	Delete bool
	Fields []Field
	// An approval: the write agreed to and the approver's authority key
	// signature over it (SS 8.1: "a person agreed").
	Target   WriteRef
	Approval Sig
}

func (c *Change) marshal() []byte {
	var e enc
	e.u8(c.Kind)
	e.raw(c.Record[:])
	e.str(c.Type)
	e.bool(c.Create)
	e.bool(c.Delete)
	e.u32(uint32(len(c.Fields)))
	for _, f := range c.Fields {
		e.str(f.Name)
		e.str(f.Value)
	}
	e.raw(c.Target.Writer[:])
	e.u64(c.Target.Seq)
	e.raw(c.Target.Hash[:])
	e.raw(c.Approval[:])
	return e.b
}

func parseChange(b []byte) (*Change, error) {
	d := dec{b: b}
	c := &Change{Kind: d.u8()}
	d.fixed(c.Record[:])
	c.Type = d.str()
	c.Create = d.bool()
	c.Delete = d.bool()
	for range d.count(4096) {
		c.Fields = append(c.Fields, Field{Name: d.str(), Value: d.str()})
	}
	d.fixed(c.Target.Writer[:])
	c.Target.Seq = d.u64()
	d.fixed(c.Target.Hash[:])
	d.fixed(c.Approval[:])
	if err := d.done(); err != nil {
		return nil, err
	}
	if c.Kind != kindRecord && c.Kind != kindApproval && c.Kind != kindReseal {
		return nil, ErrBadWrite
	}
	return c, nil
}

// approvalBytes is what an approver's authority key signs.
func approvalBytes(account Hash, t WriteRef) []byte {
	var e enc
	e.raw(account[:])
	e.raw(t.Writer[:])
	e.u64(t.Seq)
	e.raw(t.Hash[:])
	return e.b
}

// Head is the newest write of one device as a summary names it.
type Head struct {
	Device DeviceID
	Seq    uint64
	Hash   Hash
}

// Summary is a device's signed statement of the state it holds (SS 9).
type Summary struct {
	Account   Hash
	Signer    DeviceID
	Num       uint64
	KeyGen    uint32
	ListNum   uint32
	ListHash  Hash
	MinClient uint32
	Heads     []Head // sorted by device
	Sig       Sig
}

func (s *Summary) signedBytes() []byte {
	var e enc
	e.raw(s.Account[:])
	e.raw(s.Signer[:])
	e.u64(s.Num)
	e.u32(s.KeyGen)
	e.u32(s.ListNum)
	e.raw(s.ListHash[:])
	e.u32(s.MinClient)
	e.u32(uint32(len(s.Heads)))
	for _, h := range s.Heads {
		e.raw(h.Device[:])
		e.u64(h.Seq)
		e.raw(h.Hash[:])
	}
	return e.b
}

// Marshal is the summary as stored.
func (s *Summary) Marshal() []byte { return append(s.signedBytes(), s.Sig[:]...) }

// ParseSummary reads a stored summary.
func ParseSummary(b []byte) (*Summary, error) {
	d := dec{b: b}
	s := &Summary{}
	d.fixed(s.Account[:])
	d.fixed(s.Signer[:])
	s.Num = d.u64()
	s.KeyGen = d.u32()
	s.ListNum = d.u32()
	d.fixed(s.ListHash[:])
	s.MinClient = d.u32()
	for range d.count(4096) {
		var h Head
		d.fixed(h.Device[:])
		h.Seq = d.u64()
		d.fixed(h.Hash[:])
		s.Heads = append(s.Heads, h)
	}
	d.fixed(s.Sig[:])
	if err := d.done(); err != nil {
		return nil, err
	}
	for i := 1; i < len(s.Heads); i++ {
		if bytes.Compare(s.Heads[i-1].Device[:], s.Heads[i].Device[:]) >= 0 {
			return nil, ErrBadWrite // one canonical form: sorted, each device once
		}
	}
	return s, nil
}
