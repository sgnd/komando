package sealdb

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/sgnd/komando/internal/sealrow"
)

// Rekey seals every record, deleted ones included, and every audit entry
// again under newKey, in one write step, then runs then (still inside that
// step, with newKey in force) for what the caller changes along with it,
// such as the readable key settings and the policy MAC under the new
// master key (SealPolicy). Nothing changes unless all of it succeeds. From
// then on the store uses newKey.
func (d *DB) Rekey(ctx context.Context, newKey *sealrow.Key, then func(*Tx) error) error {
	if newKey == nil {
		return errors.New("sealdb: no new key")
	}
	err := d.run(ctx, true, func(tx *Tx) error {
		if err := tx.resealAll(d.key, newKey); err != nil {
			return err
		}
		if then != nil {
			return then(tx)
		}
		return nil
	})
	if err == nil {
		d.key = newKey
	}
	return err
}

// resealAll seals every record and audit entry of t again, from oldKey
// to newKey, and makes newKey the key of the rest of the step.
func (t *Tx) resealAll(oldKey, newKey *sealrow.Key) error {
	type row struct {
		id, typ string
		ver     uint64
		data    []byte
	}
	var rows []row
	rs, err := t.c.QueryContext(t.ctx, `SELECT id,type,version,data FROM records`)
	if err != nil {
		return err
	}
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.typ, &r.ver, &r.data); err != nil {
			rs.Close()
			return err
		}
		rows = append(rows, r)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return err
	}
	for _, r := range rows {
		at := sealrow.Row{ID: r.id, Type: r.typ, Version: r.ver}
		plain, err := oldKey.Open(at, r.data)
		if err != nil {
			return fmt.Errorf("record %s: %w", r.id, err)
		}
		sealed, err := newKey.Seal(at, plain)
		clear(plain)
		if err != nil {
			return err
		}
		if _, err := t.c.ExecContext(t.ctx, `UPDATE records SET data=? WHERE id=?`, sealed, r.id); err != nil {
			return err
		}
	}
	var audits []row
	as, err := t.c.QueryContext(t.ctx, `SELECT id,seq,data FROM audit`)
	if err != nil {
		return err
	}
	for as.Next() {
		var r row
		if err := as.Scan(&r.id, &r.ver, &r.data); err != nil {
			as.Close()
			return err
		}
		audits = append(audits, r)
	}
	as.Close()
	if err := as.Err(); err != nil {
		return err
	}
	for _, r := range audits {
		at := sealrow.Row{ID: r.id, Type: auditType, Version: r.ver}
		plain, err := oldKey.Open(at, r.data)
		if err != nil {
			return fmt.Errorf("audit %d: %w", r.ver, err)
		}
		sealed, err := newKey.Seal(at, plain)
		if err != nil {
			return err
		}
		if _, err := t.c.ExecContext(t.ctx, `UPDATE audit SET data=? WHERE id=?`, sealed, r.id); err != nil {
			return err
		}
	}
	t.key = newKey
	return nil
}

// setFormat sets the store's format, and its sealed copy of the meta
// table with it.
func (t *Tx) setFormat(n int) error {
	have, match, err := t.metaSealState()
	if err != nil {
		return err
	}
	if have && !match {
		return ErrMetaTampered
	}
	if _, err := t.c.ExecContext(t.ctx, `UPDATE meta SET v=? WHERE k='format'`, strconv.Itoa(n)); err != nil {
		return err
	}
	if !have {
		return nil
	}
	return t.SealMeta()
}
