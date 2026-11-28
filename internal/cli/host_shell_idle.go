package cli

import (
	"io"
	"sync/atomic"
	"time"
)

// shellIdleLimit ends a key's shell session that has had no input and no
// output for this long.
const shellIdleLimit = 30 * time.Minute

// clock is the time a session reads; tests replace shellClock.
type clock struct {
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

var shellClock = clock{now: time.Now, after: time.After}

// idleWatch tells when no byte has gone in or out for limit.
type idleWatch struct {
	limit time.Duration
	clk   clock
	last  atomic.Int64 // UnixNano of the last byte in or out
}

func newIdleWatch(limit time.Duration, clk clock) *idleWatch {
	w := &idleWatch{limit: limit, clk: clk}
	w.touch()
	return w
}

func (w *idleWatch) touch() { w.last.Store(w.clk.now().UnixNano()) }

// wait returns true once nothing has gone in or out for the limit, or false
// when done is closed first.
func (w *idleWatch) wait(done <-chan struct{}) bool {
	for {
		left := w.limit - w.clk.now().Sub(time.Unix(0, w.last.Load()))
		if left <= 0 {
			return true
		}
		select {
		case <-w.clk.after(left):
		case <-done:
			return false
		}
	}
}

// reader and writer count each byte through them as activity.
func (w *idleWatch) reader(r io.Reader) io.Reader {
	if r == nil {
		return nil
	}
	return idleReader{r, w}
}

func (w *idleWatch) writer(wr io.Writer) io.Writer {
	if wr == nil {
		return nil // an SSH session discards what has no writer
	}
	return idleWriter{wr, w}
}

type idleReader struct {
	r io.Reader
	w *idleWatch
}

func (r idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.w.touch()
	}
	return n, err
}

type idleWriter struct {
	wr io.Writer
	w  *idleWatch
}

func (w idleWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.w.touch()
	}
	return w.wr.Write(p)
}
