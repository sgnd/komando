package cli

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeShell stands in for the SSH session of a login shell: Wait returns
// what the test sends on end, or an error once the session is closed.
type fakeShell struct {
	resized   chan [2]int // WindowChange's h, w
	end       chan error
	closed    chan struct{}
	closeOnce sync.Once
	in        io.Reader
	out       io.Writer
}

func newFakeShell() *fakeShell {
	return &fakeShell{resized: make(chan [2]int, 4), end: make(chan error, 1), closed: make(chan struct{})}
}

func (f *fakeShell) RequestPty(string, int, int, ssh.TerminalModes) error { return nil }
func (f *fakeShell) Attach(in io.Reader, out, _ io.Writer)                { f.in, f.out = in, out }
func (f *fakeShell) Shell() error                                         { return nil }
func (f *fakeShell) WindowChange(h, w int) error                          { f.resized <- [2]int{h, w}; return nil }
func (f *fakeShell) Close() error                                         { f.closeOnce.Do(func() { close(f.closed) }); return nil }
func (f *fakeShell) Wait() error {
	select {
	case err := <-f.end:
		return err
	case <-f.closed:
		return errors.New("session closed")
	}
}

// fakeTerm stands in for the terminal on stdin: its size is set by the
// test, and a send on resize plays SIGWINCH.
type fakeTerm struct {
	mu     sync.Mutex
	w, h   int
	resize chan os.Signal
}

func newFakeTerm(w, h int) *fakeTerm { return &fakeTerm{w: w, h: h, resize: make(chan os.Signal, 1)} }

func (f *fakeTerm) Size() (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w, f.h, nil
}
func (f *fakeTerm) MakeRaw() (func(), error)            { return func() {}, nil }
func (f *fakeTerm) Resized() (<-chan os.Signal, func()) { return f.resize, func() {} }
func (f *fakeTerm) setSize(w, h int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w, f.h = w, h
}

// A terminal that changes size tells the remote pty its new size.
func TestShellWindowChange(t *testing.T) {
	conn, tt := newFakeShell(), newFakeTerm(80, 24)
	done := make(chan error, 1)
	go func() { done <- driveShell(conn, tt, shellIO{}, func() {}) }()
	tt.setSize(132, 43)
	tt.resize <- os.Interrupt // the channel only says the size changed (no SIGWINCH on Windows)
	select {
	case got := <-conn.resized:
		if got != [2]int{43, 132} {
			t.Errorf("window change %v, want 43 rows and 132 columns", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the new size never reached the remote pty")
	}
	conn.end <- nil
	if err := <-done; err != nil {
		t.Errorf("driveShell: %v", err)
	}
}
