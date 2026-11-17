package sealdb

import "errors"

// Stopping a handle's writes, and closing it, while other goroutines may
// still use it: their steps get a clear error, never a raw database one.

// ErrClosed: a step on a handle Close closed.
var ErrClosed = errors.New("sealdb: the store was closed")

// StopWrites makes every later write step fail with err: the store is
// read, never changed (it could not be checked, or the caller stopped
// handing this handle out). Safe while other goroutines use d; a write
// step already running ends as it would have.
func (d *DB) StopWrites(err error) { d.noWrites.Store(&err) }

// WritesStopped is the error StopWrites set, or nil.
func (d *DB) WritesStopped() error {
	if e := d.noWrites.Load(); e != nil {
		return *e
	}
	return nil
}

// stopped is the error a step fails with before it starts: the handle is
// closed, or (write) its writes were stopped.
func (d *DB) stopped(write bool) error {
	if e := d.closed.Load(); e != nil {
		return *e
	}
	if write {
		return d.WritesStopped()
	}
	return nil
}

// Close closes the store; a later step fails with ErrClosed.
func (d *DB) Close() error {
	err := ErrClosed
	d.closed.Store(&err)
	return d.db.Close()
}

// CloseIdle closes the store when no step runs on it, and reports whether
// it did; every later step fails with err. A caller that still holds the
// handle gets err, never a raw database error.
func (d *DB) CloseIdle(err error) bool {
	if !d.mu.TryLock() {
		return false
	}
	defer d.mu.Unlock()
	d.closed.Store(&err)
	_ = d.db.Close()
	return true
}
