package komandosync

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Purpose labels. Every signed or hashed byte string starts with one of
// them and a zero byte, so a signature made for one use is never accepted
// for another (SS 7.2: "every signature is tied to its use").
const (
	labelEntry      = "komando-sync/1 list entry"
	labelEntryHash  = "komando-sync/1 list entry hash"
	labelJoin       = "komando-sync/1 join"
	labelNewKit     = "komando-sync/1 new recovery kit"
	labelWrite      = "komando-sync/1 write"
	labelWriteHash  = "komando-sync/1 write hash"
	labelSummary    = "komando-sync/1 summary"
	labelApproval   = "komando-sync/1 approval"
	labelDeviceID   = "komando-sync/1 device id"
	labelKeyID      = "komando-sync/1 key id"
	labelRecord     = "komando-sync/1 record"
	labelSealDevice = "komando-sync/1 account key to device"
	labelSealKit    = "komando-sync/1 account key to kit"
	labelVaultKey   = "komando-sync/1 vault key"
	labelHistory    = "komando-sync/1 key history"
	labelSealingKey = "komando-sync/1 account sealing key"
	labelVaultID    = "komando-sync/1 personal vault"
	labelInfo       = "komando-sync/1 device info"
	labelKitSign    = "komando-sync/1 kit signing key"
	labelKitSeal    = "komando-sync/1 kit sealing key"
	labelKitCheck   = "komando-sync/1 kit check"
	labelShareCheck = "komando-sync/1 kit part check"
	labelPairBox    = "komando-sync/1 pairing mailbox"
	labelPairReq    = "komando-sync/1 pairing request"
	labelPairReply  = "komando-sync/1 pairing reply"
	labelRecordType = "komando-sync/1 record type"
	labelAuthAsk    = "komando-sync/1 new authority key"
	labelKitID      = "komando-sync/1 kit id"
)

// Hash is a SHA-256 value.
type Hash [32]byte

// DeviceID names a device: the first 16 bytes of the hash of its sync key.
type DeviceID [16]byte

// RecordID names a record. It is random and travels only inside sealed
// bodies.
type RecordID [16]byte

// sum is SHA-256(label || 0 || parts...), each part with its 4-byte
// length in front, so two lists of parts never hash the same way.
func sum(label string, parts ...[]byte) Hash {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0})
	for _, p := range parts {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
		h.Write(p)
	}
	var out Hash
	h.Sum(out[:0])
	return out
}

// enc builds the one canonical byte form of a value: big-endian integers
// of fixed width, fixed-size arrays as they are, and byte strings with a
// 4-byte length in front. Signed, hashed and bound bytes are always made
// by it, never by encoding/json or gob.
type enc struct{ b []byte }

func (e *enc) u8(v uint8)     { e.b = append(e.b, v) }
func (e *enc) u16(v uint16)   { e.b = binary.BigEndian.AppendUint16(e.b, v) }
func (e *enc) u32(v uint32)   { e.b = binary.BigEndian.AppendUint32(e.b, v) }
func (e *enc) u64(v uint64)   { e.b = binary.BigEndian.AppendUint64(e.b, v) }
func (e *enc) raw(v []byte)   { e.b = append(e.b, v...) }
func (e *enc) str(s string)   { e.bytes([]byte(s)) }
func (e *enc) bytes(v []byte) { e.u32(uint32(len(v))); e.b = append(e.b, v...) }

func (e *enc) bool(v bool) {
	if v {
		e.u8(1)
	} else {
		e.u8(0)
	}
}

// maxField bounds one length-prefixed field, so a hostile blob cannot make
// a reader allocate gigabytes.
const maxField = 16 << 20

var errShort = errors.New("komandosync: truncated or malformed data")

// dec reads what enc wrote. The first error sticks; check done() once.
type dec struct {
	b   []byte
	err error
}

func (d *dec) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = errShort
		return nil
	}
	v := d.b[:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) u8() uint8 {
	if v := d.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (d *dec) u16() uint16 {
	if v := d.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (d *dec) u32() uint32 {
	if v := d.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (d *dec) u64() uint64 {
	if v := d.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func (d *dec) fixed(dst []byte) { copy(dst, d.take(len(dst))) }

func (d *dec) bool() bool {
	switch d.u8() {
	case 0:
		return false
	case 1:
		return true
	}
	d.fail()
	return false
}

func (d *dec) bytes() []byte {
	n := d.u32()
	if n > maxField {
		d.fail()
		return nil
	}
	v := d.take(int(n))
	if v == nil {
		return nil
	}
	return append([]byte{}, v...)
}

func (d *dec) str() string { return string(d.bytes()) }

// count reads a list length and refuses one longer than max.
func (d *dec) count(max int) int {
	n := d.u32()
	if int64(n) > int64(max) {
		d.fail()
		return 0
	}
	return int(n)
}

func (d *dec) fail() {
	if d.err == nil {
		d.err = errShort
	}
}

// done reports a decoding error, or leftover bytes: the form is canonical,
// so two encodings of one value never both decode.
func (d *dec) done() error {
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return errShort
	}
	return nil
}
