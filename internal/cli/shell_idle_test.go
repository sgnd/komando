package cli

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// sessionClock is a clock the test moves: each after() is a wait the test
// receives on waits and ends by sending on its channel.
type sessionClock struct {
	mu    sync.Mutex
	t     time.Time
	waits chan fakeWait
}

type fakeWait struct {
	d time.Duration
	c chan time.Time
}

func newSessionClock() *sessionClock {
	return &sessionClock{t: time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC), waits: make(chan fakeWait, 1)}
}

func (f *sessionClock) clock() clock { return clock{now: f.now, after: f.after} }

func (f *sessionClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *sessionClock) after(d time.Duration) <-chan time.Time {
	c := make(chan time.Time, 1)
	f.waits <- fakeWait{d, c}
	return c
}

func (f *sessionClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// nextWait is the next wait the code under test starts.
func (f *sessionClock) nextWait(t *testing.T) fakeWait {
	t.Helper()
	select {
	case w := <-f.waits:
		return w
	case <-time.After(10 * time.Second):
		t.Fatal("no wait started")
		return fakeWait{}
	}
}

// Input and output each move the limit; only a whole limit with neither
// ends the wait.
func TestIdleWatchLimit(t *testing.T) {
	fc := newSessionClock()
	w := newIdleWatch(30*time.Minute, fc.clock())
	res := make(chan bool, 1)
	go func() { res <- w.wait(make(chan struct{})) }()

	wt := fc.nextWait(t)
	if wt.d != 30*time.Minute {
		t.Fatalf("first wait %v, want 30m", wt.d)
	}
	fc.advance(20 * time.Minute)
	if _, err := w.reader(strings.NewReader("x")).Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	wt.c <- fc.now()
	if wt = fc.nextWait(t); wt.d != 30*time.Minute {
		t.Fatalf("after input the wait is %v, want 30m again", wt.d)
	}
	fc.advance(29 * time.Minute)
	if _, err := w.writer(&bytes.Buffer{}).Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	wt.c <- fc.now()
	if wt = fc.nextWait(t); wt.d != 30*time.Minute {
		t.Fatalf("after output the wait is %v, want 30m again", wt.d)
	}
	fc.advance(10 * time.Minute)
	wt.c <- fc.now()
	if wt = fc.nextWait(t); wt.d != 20*time.Minute {
		t.Fatalf("10m into the limit the wait is %v, want the 20m left", wt.d)
	}
	fc.advance(20 * time.Minute)
	wt.c <- fc.now()
	select {
	case idle := <-res:
		if !idle {
			t.Error("the wait ended without the limit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("30 minutes with no input or output did not end the wait")
	}
}

// A session that ends first stops the wait.
func TestIdleWatchDone(t *testing.T) {
	fc := newSessionClock()
	w := newIdleWatch(30*time.Minute, fc.clock())
	done := make(chan struct{})
	res := make(chan bool, 1)
	go func() { res <- w.wait(done) }()
	fc.nextWait(t)
	close(done)
	if idle := <-res; idle {
		t.Error("an ended session counts as idle")
	}
}
