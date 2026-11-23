package sealdb

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shortWaits makes SQLite give up on a held lock after 50 ms in one try,
// and a write step keep trying for total; the store must be opened after.
func shortWaits(t *testing.T, total time.Duration) {
	t.Helper()
	savedBusy, savedWait := busyTimeout, writeWait
	busyTimeout, writeWait = 50*time.Millisecond, total
	t.Cleanup(func() { busyTimeout, writeWait = savedBusy, savedWait })
}

// holdLock opens path as another process would and takes a lock in a step
// that ends after hold: "BEGIN IMMEDIATE" holds the write lock; "BEGIN"
// with a read holds a reader's lock, which a commit must wait for.
func holdLock(t *testing.T, path, begin string, hold time.Duration) (released <-chan struct{}) {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	c, err := raw.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecContext(ctx, begin); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := c.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(hold)
		_, _ = c.ExecContext(ctx, "ROLLBACK")
		c.Close()
	}()
	t.Cleanup(func() { <-done })
	return done
}

func countServers(t *testing.T, d *DB) int {
	t.Helper()
	n := 0
	if err := d.View(ctx, func(tx *Tx) error {
		l, err := tx.List("server")
		n = len(l)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// Another process holds the write lock longer than SQLite waits in one
// try: the write step tries again and lands once the lock is free.
func TestUpdateWaitsOutHeldWriteLock(t *testing.T) {
	shortWaits(t, 10*time.Second)
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	holdLock(t, path, "BEGIN IMMEDIATE", 400*time.Millisecond)
	start := time.Now()
	err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err })
	if err != nil {
		t.Fatalf("a write after the lock was freed failed: %v", err)
	}
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("the write did not wait for the held lock (%s)", took)
	}
	if n := countServers(t, d); n != 1 {
		t.Fatalf("%d records, want 1", n)
	}
}

// A reader holds its lock when the write step commits: COMMIT waits for
// it and tries again, with the step's changes kept, run once.
func TestUpdateCommitWaitsForReader(t *testing.T) {
	shortWaits(t, 10*time.Second)
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	holdLock(t, path, "BEGIN", 400*time.Millisecond)
	runs := 0
	err := d.Update(ctx, func(tx *Tx) error {
		runs++
		_, err := tx.Put("server", "", []byte("a"))
		return err
	})
	if err != nil {
		t.Fatalf("a commit after the reader left failed: %v", err)
	}
	if runs != 1 {
		t.Fatalf("the step ran %d times, want once", runs)
	}
	if n := countServers(t, d); n != 1 {
		t.Fatalf("%d records, want 1", n)
	}
}

// Past writeWait the step gives up with ErrBusy and a message that says
// why, and nothing of it is written.
func TestUpdateBusyPastWaitIsErrBusy(t *testing.T) {
	shortWaits(t, 300*time.Millisecond)
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	released := holdLock(t, path, "BEGIN IMMEDIATE", 2*time.Second)
	start := time.Now()
	err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err })
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err %v, want ErrBusy", err)
	}
	if !strings.Contains(err.Error(), "another komando process") {
		t.Errorf("message does not say why: %v", err)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Errorf("gave up after %s, past the 300ms wait", took)
	}
	<-released
	if n := countServers(t, d); n != 0 {
		t.Fatalf("%d records after a failed write, want 0", n)
	}
}

// A write step tells OnWait once, at its first busy answer, even when it
// waits both to take the lock and to commit; a step that never meets
// another process tells nothing.
func TestUpdateTellsOnWait(t *testing.T) {
	shortWaits(t, 10*time.Second)
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	var told atomic.Int32
	d.OnWait = func() { told.Add(1) }
	// a writer holds the lock 300 ms, a reader its lock 700 ms: the step
	// waits for the lock, then again to commit
	holdLock(t, path, "BEGIN IMMEDIATE", 300*time.Millisecond)
	holdLock(t, path, "BEGIN", 700*time.Millisecond)
	start := time.Now()
	if err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err }); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 600*time.Millisecond {
		t.Fatalf("the step did not wait to commit (%s)", took)
	}
	if n := told.Load(); n != 1 {
		t.Fatalf("OnWait told %d times for a step that waited twice, want once", n)
	}
	// a step that does not wait tells nothing
	told.Store(0)
	if err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("b")); return err }); err != nil {
		t.Fatal(err)
	}
	if n := told.Load(); n != 0 {
		t.Fatalf("OnWait told %d times for a step that did not wait", n)
	}
}

// A slow statement that never answers busy (a slow disk flush, no other
// process) tells nothing: only a busy answer shows another process.
func TestSlowStepWithoutBusyTellsNothing(t *testing.T) {
	var told atomic.Int32
	n := &waitNotice{tell: func() { told.Add(1) }}
	if err := retryBusy(ctx, true, "commit", n, func() error { time.Sleep(300 * time.Millisecond); return nil }); err != nil {
		t.Fatal(err)
	}
	if told.Load() != 0 {
		t.Fatal("a slow statement with no busy answer told OnWait")
	}
}

// No try starts that could run past writeWait: SQLite can sit in one try
// for busyTimeout, so the step gives up by writeWait, not writeWait plus
// one more busyTimeout.
func TestUpdateGivesUpByWriteWait(t *testing.T) {
	savedBusy, savedWait := busyTimeout, writeWait
	busyTimeout, writeWait = 200*time.Millisecond, 500*time.Millisecond
	t.Cleanup(func() { busyTimeout, writeWait = savedBusy, savedWait })
	path := filepath.Join(t.TempDir(), "store.db")
	d := open(t, path)
	holdLock(t, path, "BEGIN IMMEDIATE", 3*time.Second)
	start := time.Now()
	err := d.Update(ctx, func(tx *Tx) error { _, err := tx.Put("server", "", []byte("a")); return err })
	took := time.Since(start)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err %v, want ErrBusy", err)
	}
	if took > writeWait+100*time.Millisecond {
		t.Fatalf("gave up after %s, past writeWait %s", took, writeWait)
	}
}
