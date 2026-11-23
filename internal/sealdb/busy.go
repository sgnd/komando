package sealdb

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"modernc.org/sqlite"
)

// WriteWait is how long a write step keeps trying, in all, to take the
// write lock and, separately, to commit, while other komando processes
// hold the store. Past it the step fails with ErrBusy.
const WriteWait = 60 * time.Second

// busyTimeout and writeWait are BusyTimeout and WriteWait; tests shorten
// them.
var busyTimeout, writeWait = BusyTimeout, WriteWait

// waitNotice tells OnWait once per write step, at the step's first busy
// answer: only then is another process known to hold the store (a slow
// disk flush alone answers nothing). BEGIN and COMMIT share one.
type waitNotice struct {
	once sync.Once
	tell func()
}

// busy is called at each busy answer.
func (n *waitNotice) busy() {
	if n != nil && n.tell != nil {
		n.once.Do(n.tell)
	}
}

// ErrBusy: other komando processes held the store past WriteWait.
var ErrBusy = errors.New("sealdb: store busy")

// retryBusy runs stmt, and in a write step runs it again while SQLite
// answers SQLITE_BUSY: another process held the lock past busyTimeout.
// It pauses between tries (20 ms, doubling to 1 s) and gives up with
// ErrBusy rather than start a try that could run past writeWait (SQLite
// may sit in one try for busyTimeout), so the step waits at most about
// writeWait here. Only BEGIN IMMEDIATE and COMMIT come here: the first
// has done nothing yet, and a busy COMMIT keeps the step open, so trying
// again keeps every write step whole and run once. A read step is not
// retried: its fn may have run already. A busy answer tells notice.
func retryBusy(ctx context.Context, write bool, what string, notice *waitNotice, stmt func() error) error {
	start := time.Now()
	pause := 20 * time.Millisecond
	for {
		err := stmt()
		if err == nil || !write || !isBusy(err) {
			return err
		}
		notice.busy()
		if time.Since(start)+pause+busyTimeout > writeWait {
			return fmt.Errorf("%w: could not %s for %s, while another komando process kept the store locked: %w", ErrBusy, what, writeWait, err)
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		pause = min(2*pause, time.Second)
	}
}

// IsBusy reports a step that failed because other komando processes held
// the store: a write step past WriteWait (ErrBusy), or a read step SQLite
// gave up on after BusyTimeout.
func IsBusy(err error) bool { return errors.Is(err, ErrBusy) || isBusy(err) }

// isBusy: SQLite gave up waiting for another connection's lock
// (SQLITE_BUSY, 5, in the low byte of an extended code).
func isBusy(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) && e.Code()&0xff == 5
}
