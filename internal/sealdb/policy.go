package sealdb

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/sgnd/komando/internal/sealrow"
)

// The policy MAC (C234). The row key opens and seals every record, so a
// process that holds only the row key could rewrite any row. The safety
// rows (what of a record a person must agree to change: protected marks,
// deny rules, pinned host keys, the meta seal ...) are bound by an
// HMAC-SHA256 under the policy key, which only the holder of the master
// key can make. One record keeps it beside the data: every safety row by
// type and ID with the SHA-256 of what of it is covered, then the HMAC of
// that list. Every step of a store with a policy checks the rows against
// it; a write step that changed them writes it again in the same step.
//
// A store of format 1 has no MAC; Upgrade gives it one, once. A store of
// format 2 without one is ErrPolicyMissing: it is never made again.
//
// Changing what a Part covers changes every MAC: it needs a new format
// and an upgrade, like this one.

const policyID, policyType = "policymac", "policymac"

// policyFormat is the layout of the policymac record: this byte, the
// HMAC, the list.
const policyFormat byte = 1

// Part says what of a record its type's MAC covers: nil when the record
// holds nothing it covers (a server without a safety mark). label names
// the row in an error; it is not covered.
type Part func(data []byte) (covered []byte, label string, err error)

// Whole covers a record whole.
func Whole(data []byte) ([]byte, string, error) {
	if data == nil {
		data = []byte{}
	}
	return data, "", nil
}

// Policy is the policy key and the record types whose rows it covers.
type Policy struct {
	key   []byte
	parts map[string]Part
}

// NewPolicy makes the policy for key (sealkey.Policy) over parts. The
// store's meta seal is always covered whole.
func NewPolicy(key []byte, parts map[string]Part) (*Policy, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("sealdb: policy key is %d bytes, want %d", len(key), sha256.Size)
	}
	p := &Policy{key: bytes.Clone(key), parts: maps.Clone(parts)}
	if p.parts == nil {
		p.parts = map[string]Part{}
	}
	delete(p.parts, policyType)
	p.parts[metaSealType] = func(b []byte) ([]byte, string, error) {
		c, _, err := Whole(b)
		return c, "the store's meta seal", err
	}
	return p, nil
}

// ErrPolicyMissing: a store of format 2 without its policy MAC.
var ErrPolicyMissing = fmt.Errorf("the store's safety rows have no policy MAC: %w", ErrTampered)

// PolicyError: a safety row does not match the policy MAC.
type PolicyError struct {
	Type, ID string
	Label    string // the row's name, when the record is there to read it
	// Change is "changed", "added" (a row the MAC does not list) or
	// "removed" (a row it lists that is gone or has no mark now); "" when
	// the policymac record itself does not match the policy key.
	Change string
	More   int // how many other rows differ too
}

func (e *PolicyError) Error() string {
	if e.Change == "" {
		return "sealdb: the safety rows' policy MAC does not match the policy key"
	}
	s := fmt.Sprintf("sealdb: safety row %s %s", e.Type, e.ID)
	if e.Label != "" {
		s += " (" + e.Label + ")"
	}
	s += " was " + e.Change + " without the policy key"
	if e.More > 0 {
		s += fmt.Sprintf(", and %d more", e.More)
	}
	return s
}

func (e *PolicyError) Unwrap() error { return ErrTampered }

// polRow is one safety row as the MAC lists it.
type polRow struct {
	typ, id string
	sum     [sha256.Size]byte
	label   string // not in the list
}

func cmpRow(a, b polRow) int { return cmp.Or(cmp.Compare(a.typ, b.typ), cmp.Compare(a.id, b.id)) }

// rows lists t's safety rows by type, then ID.
func (p *Policy) rows(t *Tx) ([]polRow, error) {
	var out []polRow
	for _, typ := range slices.Sorted(maps.Keys(p.parts)) {
		recs, err := t.List(typ)
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			c, label, err := p.parts[typ](r.Data)
			if err != nil {
				return nil, fmt.Errorf("record %s: %w", r.ID, err)
			}
			if c != nil {
				out = append(out, polRow{typ: typ, id: r.ID, sum: sha256.Sum256(c), label: label})
			}
		}
	}
	slices.SortFunc(out, cmpRow)
	return out, nil
}

func encodeRows(rs []polRow) []byte {
	var b []byte
	for _, r := range rs {
		for _, s := range []string{r.typ, r.id} {
			b = binary.AppendUvarint(b, uint64(len(s)))
			b = append(b, s...)
		}
		b = append(b, r.sum[:]...)
	}
	return b
}

func decodeRows(b []byte) ([]polRow, bool) {
	var rs []polRow
	for len(b) > 0 {
		var r polRow
		for _, s := range []*string{&r.typ, &r.id} {
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, false
			}
			*s, b = string(b[n:n+int(l)]), b[n+int(l):]
		}
		if len(b) < sha256.Size {
			return nil, false
		}
		copy(r.sum[:], b)
		rs, b = append(rs, r), b[sha256.Size:]
	}
	return rs, true
}

func (p *Policy) tag(list []byte) []byte {
	h := hmac.New(sha256.New, p.key)
	h.Write([]byte{policyFormat})
	h.Write(list)
	return h.Sum(nil)
}

// check compares t's safety rows with the MAC and returns them.
func (p *Policy) check(t *Tx) ([]polRow, error) {
	r, err := t.Get(policyID)
	if errors.Is(err, ErrNotFound) || err == nil && r.Deleted {
		return nil, ErrPolicyMissing
	}
	if err != nil {
		return nil, err
	}
	d := r.Data
	if len(d) < 1+sha256.Size || d[0] != policyFormat || !hmac.Equal(d[1:1+sha256.Size], p.tag(d[1+sha256.Size:])) {
		return nil, &PolicyError{Type: policyType, ID: policyID}
	}
	kept, ok := decodeRows(d[1+sha256.Size:])
	if !ok {
		return nil, &PolicyError{Type: policyType, ID: policyID}
	}
	now, err := p.rows(t)
	if err != nil {
		return nil, err
	}
	if e := diffRows(kept, now); e != nil {
		if e.Label == "" {
			e.Label = p.label(t, e.Type, e.ID)
		}
		return nil, e
	}
	return now, nil
}

// diffRows is the first row where kept and now differ, nil when none.
func diffRows(kept, now []polRow) *PolicyError {
	var first *PolicyError
	note := func(r polRow, change string) {
		if first == nil {
			first = &PolicyError{Type: r.typ, ID: r.id, Label: r.label, Change: change}
		} else {
			first.More++
		}
	}
	i, j := 0, 0
	for i < len(kept) || j < len(now) {
		switch {
		case j == len(now) || i < len(kept) && cmpRow(kept[i], now[j]) < 0:
			note(kept[i], "removed")
			i++
		case i == len(kept) || cmpRow(kept[i], now[j]) > 0:
			note(now[j], "added")
			j++
		default:
			if kept[i].sum != now[j].sum {
				note(now[j], "changed")
			}
			i, j = i+1, j+1
		}
	}
	return first
}

// label names a row that has no safety mark now, when it is still there.
func (p *Policy) label(t *Tx, typ, id string) string {
	part := p.parts[typ]
	r, err := t.rawGet(id)
	if part == nil || err != nil || r.Deleted || r.Type != typ {
		return ""
	}
	_, l, _ := part(r.Data)
	return l
}

// putPolicy writes the MAC over rows.
func (t *Tx) putPolicy(p *Policy, rows []polRow) error {
	list := encodeRows(rows)
	b := append([]byte{policyFormat}, p.tag(list)...)
	_, err := t.Put(policyType, policyID, append(b, list...))
	return err
}

// SealPolicy writes the policy MAC over the safety rows as they are now,
// and makes p the policy of this step, and of the store once the step is
// kept: on a new store, on an upgrade, and with a new master key (store
// Rekey).
func (t *Tx) SealPolicy(p *Policy) error {
	if !t.write {
		return ErrReadOnly
	}
	rows, err := p.rows(t)
	if err != nil {
		return err
	}
	if err := t.putPolicy(p, rows); err != nil {
		return err
	}
	t.pol, t.polRows, t.newPol = p, rows, p
	return nil
}

// keepPolicy writes the MAC again at the end of a write step that changed
// a safety row.
func (t *Tx) keepPolicy() error {
	if t.pol == nil {
		return nil
	}
	touched := false
	for id := range t.ix.touched {
		var typ string
		err := t.c.QueryRowContext(t.ctx, `SELECT type FROM records WHERE id=?`, id).Scan(&typ)
		if err == nil && t.pol.parts[typ] != nil {
			touched = true
			break
		}
	}
	if !touched {
		return nil
	}
	rows, err := t.pol.rows(t)
	if err != nil {
		return err
	}
	if slices.EqualFunc(rows, t.polRows, func(a, b polRow) bool { return cmpRow(a, b) == 0 && a.sum == b.sum }) {
		return nil
	}
	if err := t.putPolicy(t.pol, rows); err != nil {
		return err
	}
	t.polRows = rows
	return nil
}

// SetPolicy checks the store's safety rows against their policy MAC and,
// when they match, makes every later step check them too. Call it right
// after Open, before the store is shared.
func (d *DB) SetPolicy(ctx context.Context, p *Policy) error {
	err := d.View(ctx, func(tx *Tx) error {
		_, err := p.check(tx)
		return err
	})
	if err == nil {
		d.policy.Store(p)
	}
	return err
}

// Upgrade moves a format-1 store to this format in one write step: every
// record and audit entry is sealed again under rowKey, the format goes
// up, and the safety rows get their policy MAC. From then on the store
// uses rowKey and p.
func (d *DB) Upgrade(ctx context.Context, rowKey *sealrow.Key, p *Policy) error {
	if rowKey == nil || p == nil {
		return errors.New("sealdb: an upgrade needs the new row key and the policy")
	}
	err := d.run(ctx, true, func(tx *Tx) error {
		if v, err := tx.Meta("format"); err != nil || v != "1" {
			return cmp.Or(err, fmt.Errorf("sealdb: the store is of format %q, not 1", v))
		}
		if err := tx.resealAll(d.key, rowKey); err != nil {
			return err
		}
		if err := tx.setFormat(Format); err != nil {
			return err
		}
		return tx.SealPolicy(p)
	})
	if err == nil {
		d.key = rowKey
	}
	return err
}
