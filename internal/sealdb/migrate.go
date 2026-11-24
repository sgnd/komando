package sealdb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/sgnd/komando/internal/sealrow"
)

// ErrSafetyChanged: a migration would have changed a safety row it must
// carry as it was.
var ErrSafetyChanged = errors.New("sealdb: the migration changed a safety row")

// auditPage is how many audit entries one read of the chain check takes.
const auditPage = 1000

// Migrate moves the store from format from to format to in one write
// step: it checks the audit chain, seals every record and audit entry
// again under rowKey, lets change rewrite records, sets the format, seals
// the policy MAC under p, and checks the chain again. The safety rows must
// come out as they went in (only their labels may differ), then verify
// reads the result inside the same step. Any error undoes all of it.
//
// The handle must check the store's own policy MAC (SetPolicy), so a row
// changed outside komando is never sealed under a new MAC. Once the step
// is kept this handle takes no more writes: the code that holds it reads
// format from.
func (d *DB) Migrate(ctx context.Context, from, to int, rowKey *sealrow.Key, p *Policy, change, verify func(*Tx) error) error {
	if rowKey == nil || p == nil {
		return errors.New("sealdb: a migration needs the new row key and the policy")
	}
	if d.policy.Load() == nil {
		return fmt.Errorf("sealdb: the store was opened without its policy: %w", ErrPolicyMissing)
	}
	err := d.run(ctx, true, func(tx *Tx) error {
		if v, err := tx.Meta("format"); err != nil || v != strconv.Itoa(from) {
			return errors.Join(err, fmt.Errorf("sealdb: the store is of format %q, not %d", v, from))
		}
		if err := tx.checkChain(); err != nil {
			return err
		}
		kept := tx.polRows
		if err := tx.resealAll(d.key, rowKey); err != nil {
			return err
		}
		if err := change(tx); err != nil {
			return err
		}
		if err := tx.setFormat(to); err != nil {
			return err
		}
		if err := tx.SealPolicy(p); err != nil {
			return err
		}
		// the meta seal holds the format, so it changes here on purpose;
		// setFormat refused a tampered one first
		if e := diffRows(withoutMetaSeal(kept), withoutMetaSeal(tx.polRows)); e != nil {
			return fmt.Errorf("%w: %w", ErrSafetyChanged, e)
		}
		if err := tx.checkChain(); err != nil {
			return err
		}
		return verify(tx)
	})
	if err != nil {
		return err
	}
	d.key = rowKey
	d.StopWrites(fmt.Errorf("%w: the store is of format %d now", ErrNewerFormat, to))
	return nil
}

func withoutMetaSeal(rows []polRow) []polRow {
	return slices.DeleteFunc(slices.Clone(rows), func(r polRow) bool { return r.typ == metaSealType })
}

// checkChain reads the whole audit chain; a missing, moved or damaged
// entry stops it with ErrTampered.
func (t *Tx) checkChain() error {
	var after int64
	for {
		rows, err := t.Audit(after, auditPage)
		if err != nil {
			return err
		}
		if len(rows) < auditPage {
			return nil
		}
		after = rows[len(rows)-1].Seq
	}
}
