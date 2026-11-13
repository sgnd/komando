package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealrow"
)

// MovedNote replaces each file of before once a folder is sealed (komando
// seal). It is not valid data for any of them, so a komando from before
// the sealed store stops with an error instead of starting with an empty
// folder (no protected servers, no deny rules, no pinned host keys).
const MovedNote = "This komando folder was moved to komando's sealed store (store.db).\nUpdate komando: https://github.com/sgnd/komando#install\n"

// IsMovedNote reports a file that holds MovedNote.
func IsMovedNote(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.HasPrefix(b, []byte(MovedNote[:40]))
}

// AppendAuditLines adds audit records of before to a sealed store, as they
// are, in one write step.
func AppendAuditLines(lines [][]byte) error {
	d, err := DB(true)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		for _, l := range lines {
			if err := tx.AppendAudit(l); err != nil {
				return err
			}
		}
		return nil
	})
}

// RemoveStore takes a store away (a move that did not finish, or its
// undo): store.db is renamed to name, never deleted, and this process
// forgets it.
func RemoveStore(name string) error {
	// one empty write step waits for any other writer and replays a
	// journal left by a crash, so the copy set aside is whole
	if d, err := DB(false); err == nil {
		_ = d.Update(context.Background(), func(*sealdb.Tx) error { return nil })
	}
	closeDBs()
	err := os.Rename(Path(StoreFile), Path(name))
	if err == nil {
		// a journal still there belongs to a write in flight: it goes with
		// its store, never away
		if jerr := os.Rename(Path(StoreFile+"-journal"), Path(name+"-journal")); jerr != nil && !errors.Is(jerr, os.ErrNotExist) {
			err = jerr
		}
	}
	if err == nil && GenerationKeeper.Del != nil {
		GenerationKeeper.Del() // no store, no count to compare with
	}
	return err
}

// AuditCount is how many audit records the store holds (the move keeps it
// in the archive, so an undo can carry the ones written after).
func AuditCount() (int64, error) {
	d, err := DB(false)
	if err != nil {
		return 0, err
	}
	var n int64
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.Audit(0, 1<<30)
		n = int64(len(rows))
		return err
	})
	return n, err
}

// AuditAfter gives the audit records after the first n, as written.
func AuditAfter(n int64) ([][]byte, error) {
	d, err := DB(false)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.Audit(n, 1<<30)
		for _, r := range rows {
			out = append(out, r.Data)
		}
		return err
	})
	return out, err
}

var archiveMagic = []byte("komando-archive-sealed-1\n")

var archiveRow = sealrow.Row{ID: "before-seal", Type: "archive", Version: 1}

// The archive has a key of its own, kept as a record in the store: the
// store's records are sealed again when its key changes (secret
// passphrase, secret keychain), so the archive opens for as long as the
// store does.
const archiveKeyID, archiveKeyType = "archivekey", "archivekey"

func archiveKey(create bool) (*sealrow.Key, error) {
	d, err := DB(create)
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		r, err := tx.Get(archiveKeyID)
		if err == nil && !r.Deleted {
			raw = r.Data
			return nil
		}
		if !create {
			return errors.New("the store holds no archive key")
		}
		raw = make([]byte, sealrow.MasterLen)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		_, err = tx.Put(archiveKeyType, archiveKeyID, raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return sealrow.NewKey(raw)
}

// SealArchive seals data with the store's archive key, for the archive of
// the files of before.
func SealArchive(data []byte) ([]byte, error) {
	k, err := archiveKey(true)
	if err != nil {
		return nil, err
	}
	s, err := k.Seal(archiveRow, data)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, archiveMagic...), s...), nil
}

// OpenArchive opens what SealArchive made.
func OpenArchive(b []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(b, archiveMagic)
	if !ok {
		return nil, errors.New("not an archive made by komando seal")
	}
	k, err := archiveKey(false)
	if err != nil {
		return nil, err
	}
	return k.Open(archiveRow, rest)
}

// OpenRuntimeFile gives runtime.json's content, opened when it is sealed
// (the undo puts it back plain).
func OpenRuntimeFile() ([]byte, error) {
	b, err := os.ReadFile(runtimePath())
	if err != nil {
		return nil, err
	}
	return openRuntime(b)
}
