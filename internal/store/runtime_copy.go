package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/sealdb"
)

// The runtime records that outlive a store migration (Audit Q7): exec
// sessions and jobs run on servers, and their record on this computer is
// the only way to read or stop them. The migration writes them into
// store.db in its own write step, under the new runtime mark, and then
// writes runtime.json from that copy. A runtime.json whose mark does not
// match store.db is rebuilt from the copy when the copy carries the
// store's mark: a crash between the commit and runtime.json loses nothing.

const (
	kindRuntimeCopy = "runtimecopy"
	runtimeCopyID   = "runtime-copy"
)

type runtimeCopy struct {
	Mark         string                  `json:"mark"`
	Jobs         map[string]*Job         `json:"jobs,omitempty"`
	ExecSessions map[string]*ExecSession `json:"exec_sessions,omitempty"`
}

// carriedRuntime is what of runtime.json the migration carries, read
// against the format-2 store d. The caller holds the store lock and has
// checked that no local komando process runs, so VPN sessions, logins and
// tunnels are over.
func carriedRuntime(ctx context.Context, d *sealdb.DB) (*Runtime, error) {
	s := &State{}
	err := d.View(ctx, func(tx *sealdb.Tx) error {
		var err error
		s.runtimeMark, err = readRuntimeMark(tx)
		return err
	})
	if err == nil {
		err = s.loadRuntime()
	}
	if err != nil {
		return nil, err
	}
	c := &Runtime{Jobs: s.Runtime.Jobs, ExecSessions: s.Runtime.ExecSessions}
	c.init()
	return c, nil
}

// putRuntimeCopy writes rt's carried records and a new runtime mark in
// tx, and returns the mark.
func putRuntimeCopy(tx *sealdb.Tx, rt *Runtime) (string, error) {
	mark, err := putRuntimeMark(tx)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(runtimeCopy{Mark: mark, Jobs: rt.Jobs, ExecSessions: rt.ExecSessions})
	if err != nil {
		return "", err
	}
	_, err = tx.Put(kindRuntimeCopy, runtimeCopyID, b)
	return mark, err
}

// readRuntimeCopy is store.db's copy of the carried records when it holds
// one written under mark, else nil.
func readRuntimeCopy(tx *sealdb.Tx, mark string) (*runtimeCopy, error) {
	r, err := tx.Get(runtimeCopyID)
	if errors.Is(err, sealdb.ErrNotFound) || err == nil && r.Deleted {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c runtimeCopy
	if err := json.Unmarshal(r.Data, &c); err != nil {
		return nil, err
	}
	if mark == "" || c.Mark != mark {
		return nil, nil
	}
	return &c, nil
}

// fromCopy is the runtime data a runtime.json with another mark is read
// as: the store's copy when it carries mark, else empty.
func fromCopy(mark string, c *runtimeCopy) Runtime {
	rt := Runtime{Mark: mark}
	if c != nil {
		rt.Jobs, rt.ExecSessions = c.Jobs, c.ExecSessions
	}
	rt.init()
	return rt
}

// syncDir flushes a folder's entries (a rename in it) to disk.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
