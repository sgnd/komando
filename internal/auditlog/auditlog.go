package auditlog

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

// On a sealed home the audit log is the store's audit table: each record is
// sealed and bound to its number, so an edited, moved or removed record
// stops `audit verify` at that number, and no one reads it from the file.
// The chain's "prev" field is not needed there.

func Append(rec map[string]any) ([]byte, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	d, err := store.DB(true)
	if err != nil {
		return nil, err
	}
	return b, d.Update(context.Background(), func(tx *sealdb.Tx) error { return tx.AppendAudit(b) })
}

// Page is how many records one short read step returns, so reading
// the log never holds the store for long.
const Page = 500

// Each calls fn with every audit record in the store, oldest first. A sealed record
// that does not open stops it with sealdb.ErrTampered.
func Each(fn func(n int, rec []byte) error) error { return EachAfter(0, fn) }

// NewestSeq gives the number of the newest audit record (0: none).
func NewestSeq() (int64, error) {
	d, err := store.DB(false)
	if errors.Is(err, store.ErrNoStore) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int64
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		var err error
		n, err = tx.AuditLast()
		return err
	})
	return n, err
}

// EachAfter is Each from the record after number after on.
func EachAfter(after int64, fn func(n int, rec []byte) error) error {
	d, err := store.DB(false)
	if errors.Is(err, store.ErrNoStore) {
		return nil
	}
	if err != nil {
		return err
	}
	for {
		var rows []sealdb.AuditRow
		err := d.View(context.Background(), func(tx *sealdb.Tx) error {
			var err error
			rows, err = tx.Audit(after, Page)
			return err
		})
		// the records before a broken one are still given
		for _, r := range rows {
			if ferr := fn(int(r.Seq), r.Data); ferr != nil {
				return ferr
			}
			after = r.Seq
		}
		if err != nil {
			return err
		}
		if len(rows) < Page {
			return nil
		}
	}
}

func Verify() (Check, error) {
	r := Check{OK: true, Note: "every record is sealed and numbered; an edited, moved or removed record, or records cut from the end, would stop the check"}
	last := 0
	err := Each(func(n int, _ []byte) error {
		r.Entries++
		r.Chained++
		last = n
		return nil
	})
	if errors.Is(err, sealdb.ErrTampered) {
		r.OK, r.FirstBroken = false, last+1
		r.Note = "the record with this number was changed, moved or removed outside komando"
		return r, nil
	}
	if r.Entries == 0 && err == nil {
		r.Note = "no audit log yet"
	}
	return r, err
}
