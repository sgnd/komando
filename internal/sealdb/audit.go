package sealdb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/sgnd/komando/internal/sealrow"
)

// Audit entries form a chain: each one holds, sealed, the sum of the entry
// before it, and the index (index.go) keeps the number and sum of the last
// one. An entry removed shows as a gap, one put back in another place
// breaks the chain, and entries cut from the end no longer reach the head.

// auditType is the type audit rows are sealed under, so an audit row cannot
// be opened as a record.
const auditType = "audit"

// chained marks an entry that holds the sum of the one before it; entries
// from before the chain start with 0.
const chained = 2

const sumLen = sha256.Size

func auditSum(seq int64, plain []byte) [sumLen]byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, seq)
	h.Write(plain)
	var s [sumLen]byte
	h.Sum(s[:0])
	return s
}

// openAudit opens one entry and checks its readable time.
func (t *Tx) openAudit(seq, tm int64, id string, sealed []byte) ([]byte, error) {
	plain, err := t.key.Open(sealrow.Row{ID: id, Type: auditType, Version: uint64(seq)}, sealed)
	if err != nil {
		return nil, fmt.Errorf("audit %d: %w: %w", seq, ErrTampered, err)
	}
	if len(plain) < headLen || int64(binary.BigEndian.Uint64(plain[1:])) != tm ||
		(plain[0] == chained && len(plain) < headLen+sumLen) {
		return nil, fmt.Errorf("audit %d: %w", seq, ErrTampered)
	}
	return plain, nil
}

// lastAudit is the head of the chain as the rows have it.
func (t *Tx) lastAudit() (auditHead, error) {
	var (
		seq, tm int64
		id      string
		sealed  []byte
	)
	err := t.c.QueryRowContext(t.ctx, `SELECT seq,id,time,data FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &id, &tm, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return auditHead{}, nil
	}
	if err != nil {
		return auditHead{}, err
	}
	plain, err := t.openAudit(seq, tm, id, sealed)
	if err != nil {
		return auditHead{}, err
	}
	return auditHead{seq: seq, sum: auditSum(seq, plain)}, nil
}

// AppendAudit adds one audit entry. It raises the generation like a
// changed record, so the entry cannot be cut off later unnoticed.
func (t *Tx) AppendAudit(data []byte) error {
	if !t.write {
		return ErrReadOnly
	}
	s, err := t.index()
	if err != nil {
		return err
	}
	id, err := sealrow.NewID()
	if err != nil {
		return err
	}
	seq := s.head.seq + 1
	now := time.Now().UnixNano()
	plain := head(false, now, nil)
	plain[0] = chained
	plain = append(append(plain, s.head.sum[:]...), data...)
	sealed, err := t.key.Seal(sealrow.Row{ID: id, Type: auditType, Version: uint64(seq)}, plain)
	if err != nil {
		return err
	}
	if _, err = t.c.ExecContext(t.ctx, `INSERT INTO audit(seq,id,time,data) VALUES(?,?,?,?)`, seq, id, now, sealed); err != nil {
		return err
	}
	s.head = auditHead{seq: seq, sum: auditSum(seq, plain)}
	t.changed = true
	return nil
}

// Audit returns up to limit audit entries after seq, oldest first. A
// missing, damaged or moved entry, or entries cut from the end, stop it
// with ErrTampered, together with the entries before it.
func (t *Tx) Audit(after int64, limit int) ([]AuditRow, error) {
	s, err := t.index()
	if err != nil {
		return nil, err
	}
	rows, err := t.c.QueryContext(t.ctx, `SELECT seq,id,time,data FROM audit WHERE seq>? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var (
		out  []AuditRow
		prev *[sumLen]byte
		last auditHead
	)
	want := after + 1
	for rows.Next() {
		var (
			seq, tm int64
			id      string
			sealed  []byte
		)
		if err := rows.Scan(&seq, &id, &tm, &sealed); err != nil {
			return nil, err
		}
		if seq != want {
			return out, fmt.Errorf("audit %d (want %d): %w", seq, want, ErrTampered)
		}
		want = seq + 1
		plain, err := t.openAudit(seq, tm, id, sealed)
		if err != nil {
			return out, err
		}
		data := plain[headLen:]
		if plain[0] == chained {
			if prev != nil && [sumLen]byte(data[:sumLen]) != *prev {
				return out, fmt.Errorf("audit %d: %w", seq, ErrTampered)
			}
			data = data[sumLen:]
		}
		last = auditHead{seq: seq, sum: auditSum(seq, plain)}
		prev = &last.sum
		out = append(out, AuditRow{Seq: seq, Time: time.Unix(0, tm), Data: data})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	// the end of the log must be the head the index keeps
	if len(out) < limit {
		if len(out) == 0 && after >= s.head.seq {
			return out, nil
		}
		if last != s.head {
			return out, fmt.Errorf("audit after %d: %w", last.seq, ErrTampered)
		}
	}
	return out, nil
}
