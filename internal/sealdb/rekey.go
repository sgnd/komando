package sealdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/sealrow"
)

// Rekey seals every record, deleted ones included, and every audit entry
// again under newKey, in one write step, then runs then (still inside that
// step, with newKey in force) for what the caller changes along with it,
// such as the readable key settings. Nothing changes unless all of it
// succeeds. From then on the store uses newKey.
func (d *DB) Rekey(ctx context.Context, newKey *sealrow.Key, then func(*Tx) error) error {
	if newKey == nil {
		return errors.New("sealdb: no new key")
	}
	err := d.run(ctx, true, func(tx *Tx) error {
		type row struct {
			id, typ string
			ver     uint64
			data    []byte
		}
		var rows []row
		rs, err := tx.c.QueryContext(ctx, `SELECT id,type,version,data FROM records`)
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
			plain, err := d.key.Open(at, r.data)
			if err != nil {
				return fmt.Errorf("record %s: %w", r.id, err)
			}
			sealed, err := newKey.Seal(at, plain)
			clear(plain)
			if err != nil {
				return err
			}
			if _, err := tx.c.ExecContext(ctx, `UPDATE records SET data=? WHERE id=?`, sealed, r.id); err != nil {
				return err
			}
		}
		var audits []row
		as, err := tx.c.QueryContext(ctx, `SELECT id,seq,data FROM audit`)
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
			plain, err := d.key.Open(at, r.data)
			if err != nil {
				return fmt.Errorf("audit %d: %w", r.ver, err)
			}
			sealed, err := newKey.Seal(at, plain)
			if err != nil {
				return err
			}
			if _, err := tx.c.ExecContext(ctx, `UPDATE audit SET data=? WHERE id=?`, sealed, r.id); err != nil {
				return err
			}
		}
		tx.key = newKey
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
