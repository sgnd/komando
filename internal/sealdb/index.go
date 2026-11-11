package sealdb

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// The store's index binds every record row to the store's state: the
// generation record holds, sealed, the version, type and deletion marker of
// every other record, and the head of the audit chain (audit.go). It is
// written in the same step as the generation, so a row put back from an
// older copy, a row removed, or audit entries cut from the end no longer
// match it, and reads stop with ErrTampered. Rolling the generation record
// itself back is an old copy of the store, which the keychain catches.
//
// A store from before the index has a generation record of digits only;
// its index is made from the rows as they are, and written with the next
// change.

type ixEnt struct {
	typ string
	ver uint64
	del bool
}

type auditHead struct {
	seq int64
	sum [32]byte
}

// ixState is a step's view of the index, shared by its nested steps.
type ixState struct {
	loaded  bool
	upgrade bool // made from the rows: written with the next change
	gen     uint64
	m       map[string]ixEnt
	head    auditHead
	touched map[string]bool // records written in this step
}

func (t *Tx) index() (*ixState, error) {
	s := t.ix
	if s.loaded {
		return s, nil
	}
	r, err := t.rawGet(generationID)
	switch {
	case errors.Is(err, ErrNotFound):
		// only a store that was never written has no generation record
		var n int
		if err := t.c.QueryRowContext(t.ctx, `SELECT count(*) FROM records`).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, fmt.Errorf("record %s: %w", generationID, ErrTampered)
		}
		err = t.indexFromRows(s)
	case err != nil:
		return nil, err
	default:
		err = s.decode(r.Data)
		if errors.Is(err, errNoIndex) {
			err = t.indexFromRows(s)
		}
	}
	if err != nil {
		return nil, err
	}
	s.loaded = true
	return s, nil
}

var errNoIndex = errors.New("no index")

func (s *ixState) decode(b []byte) error {
	num, rest, found := bytes.Cut(b, []byte{'\n'})
	n, err := strconv.ParseUint(string(num), 10, 64)
	if err != nil {
		return fmt.Errorf("record %s: %w", generationID, ErrTampered)
	}
	s.gen = n
	if !found {
		return errNoIndex
	}
	bad := fmt.Errorf("record %s: %w", generationID, ErrTampered)
	if len(rest) < 40 {
		return bad
	}
	s.head.seq = int64(binary.BigEndian.Uint64(rest))
	copy(s.head.sum[:], rest[8:40])
	rest = rest[40:]
	s.m = map[string]ixEnt{}
	str := func() (string, bool) {
		l, k := binary.Uvarint(rest)
		if k <= 0 || uint64(len(rest)-k) < l {
			return "", false
		}
		v := string(rest[k : k+int(l)])
		rest = rest[k+int(l):]
		return v, true
	}
	for len(rest) > 0 {
		id, ok1 := str()
		typ, ok2 := str()
		if !ok1 || !ok2 {
			return bad
		}
		ver, k := binary.Uvarint(rest)
		if k <= 0 || len(rest) < k+1 {
			return bad
		}
		s.m[id] = ixEnt{typ: typ, ver: ver, del: rest[k] != 0}
		rest = rest[k+1:]
	}
	return nil
}

func (s *ixState) encode() []byte {
	b := strconv.AppendUint(nil, s.gen, 10)
	b = append(b, '\n')
	b = binary.BigEndian.AppendUint64(b, uint64(s.head.seq))
	b = append(b, s.head.sum[:]...)
	ids := make([]string, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		e := s.m[id]
		b = binary.AppendUvarint(b, uint64(len(id)))
		b = append(b, id...)
		b = binary.AppendUvarint(b, uint64(len(e.typ)))
		b = append(b, e.typ...)
		b = binary.AppendUvarint(b, e.ver)
		d := byte(0)
		if e.del {
			d = 1
		}
		b = append(b, d)
	}
	return b
}

// indexFromRows makes the index of a store from before it, trusting the
// rows as they are.
func (t *Tx) indexFromRows(s *ixState) error {
	s.upgrade = true
	s.m = map[string]ixEnt{}
	rows, err := t.c.QueryContext(t.ctx, `SELECT id,type,version,deleted FROM records WHERE id<>?`, generationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			e  ixEnt
			id string
		)
		if err := rows.Scan(&id, &e.typ, &e.ver, &e.del); err != nil {
			return err
		}
		s.m[id] = e
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	s.head, err = t.lastAudit()
	return err
}

// checkRow stops a record row that the index does not know at this
// version; exists is false for an ID with no row.
func (t *Tx) checkRow(id string, ver uint64, exists bool) error {
	if id == generationID {
		return nil
	}
	s, err := t.index()
	if err != nil {
		return err
	}
	if s.touched[id] {
		return nil
	}
	e, ok := s.m[id]
	if ok != exists || (ok && e.ver != ver) {
		return fmt.Errorf("record %s: %w", id, ErrTampered)
	}
	return nil
}

// checkList stops a list of type typ that misses a record the index has.
func (t *Tx) checkList(typ string, seen map[string]bool) error {
	s, err := t.index()
	if err != nil {
		return err
	}
	for id, e := range s.m {
		if e.typ == typ && !e.del && !seen[id] && !s.touched[id] {
			return fmt.Errorf("record %s: %w", id, ErrTampered)
		}
	}
	return nil
}

// touch notes a record written in this step; its row is read again when
// the index is written.
func (t *Tx) touch(id string) error {
	s, err := t.index()
	if err != nil {
		return err
	}
	if s.touched == nil {
		s.touched = map[string]bool{}
	}
	s.touched[id] = true
	t.changed = true
	return nil
}

// bumpGeneration raises the generation and writes the index with it, at
// the end of a write step that changed something.
func (t *Tx) bumpGeneration() (uint64, error) {
	s, err := t.index()
	if err != nil {
		return 0, err
	}
	for id := range s.touched {
		var e ixEnt
		err := t.c.QueryRowContext(t.ctx, `SELECT type,version,deleted FROM records WHERE id=?`, id).Scan(&e.typ, &e.ver, &e.del)
		switch {
		case errors.Is(err, sql.ErrNoRows): // its write was undone
			delete(s.m, id)
		case err != nil:
			return 0, err
		default:
			s.m[id] = e
		}
	}
	s.gen++
	if _, err := t.write1(generationID, generationType, s.gen, false, s.encode()); err != nil {
		return 0, err
	}
	s.touched, s.upgrade = nil, false
	return s.gen, nil
}
