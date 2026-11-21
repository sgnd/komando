package cli

import (
	"context"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// shellConn is the SSH session a login shell runs in; tests stand in for it.
type shellConn interface {
	RequestPty(term string, h, w int, modes ssh.TerminalModes) error
	Attach(in io.Reader, out, errOut io.Writer)
	Shell() error
	Wait() error
	WindowChange(h, w int) error
	Close() error
}

// sshShell is a shellConn over a real SSH session.
type sshShell struct{ *ssh.Session }

func (s sshShell) Attach(in io.Reader, out, errOut io.Writer) {
	s.Stdin, s.Stdout, s.Stderr = in, out, errOut
}

// shellDial connects to h and runs fn with a new session there; tests
// replace it.
var shellDial = func(cl *call, ctx context.Context, st *store.State, h *store.Host, fn func(shellConn) error) error {
	return withClient(cl, ctx, st, h, func(c *sshx.Client) error {
		sess, err := c.Session()
		if err != nil {
			return err
		}
		defer sess.Close()
		return fn(sshShell{sess})
	})
}

// shellTerm is the terminal komando shell runs on; tests stand in for it.
type shellTerm interface {
	Size() (w, h int, err error)
	MakeRaw() (restore func(), err error)
	Resized() (ch <-chan os.Signal, stop func())
}

// fdTerm is the terminal on a file descriptor.
type fdTerm int

func (fd fdTerm) Size() (int, int, error) { return term.GetSize(int(fd)) }

func (fd fdTerm) MakeRaw() (func(), error) {
	old, err := term.MakeRaw(int(fd))
	if err != nil {
		return nil, err
	}
	return func() { _ = term.Restore(int(fd), old) }, nil
}

func (fd fdTerm) Resized() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	return ch, notifyResize(int(fd), ch)
}

// shellTTY is the terminal on stdin; tests replace it.
var shellTTY = func() shellTerm { return fdTerm(os.Stdin.Fd()) }

// shellIO is what the login shell reads and writes.
type shellIO struct {
	in       io.Reader
	out, err io.Writer
	idle     *idleWatch // nil: no idle limit
}

// driveShell runs the login shell on conn with sio until it ends, and
// passes each new size of the terminal tt on to the remote pty. It closes
// the session when ctx ends (hangup) or when sio.idle's limit passes
// (idle), and returns which as stop. started is called once the shell runs.
func driveShell(ctx context.Context, conn shellConn, tt shellTerm, sio shellIO, started func()) (stop string, err error) {
	in, out, errOut := sio.in, sio.out, sio.err
	if sio.idle != nil {
		in, out, errOut = sio.idle.reader(in), sio.idle.writer(out), sio.idle.writer(errOut)
	}
	conn.Attach(in, out, errOut)
	resized, stopResize := tt.Resized()
	defer stopResize()
	done := make(chan struct{})
	defer close(done)
	go forwardResize(resized, done, tt.Size, conn.WindowChange)
	if err := conn.Shell(); err != nil {
		return "", err
	}
	started()
	var mu sync.Mutex
	why := ""
	end := func(reason string) {
		mu.Lock()
		first := why == ""
		if first {
			why = reason
		}
		mu.Unlock()
		if first {
			_ = conn.Close()
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			end(sessionHangup)
		case <-done:
		}
	}()
	if sio.idle != nil {
		go func() {
			if sio.idle.wait(done) {
				end(sessionIdle)
			}
		}()
	}
	err = conn.Wait()
	mu.Lock()
	stop = why
	mu.Unlock()
	if stop == "" && ctx.Err() != nil {
		stop = sessionHangup // the connection closed on ctx before the watch saw it
	}
	return stop, err
}

// forwardResize sends the terminal's size to change on each signal on ch,
// until done is closed.
func forwardResize(ch <-chan os.Signal, done <-chan struct{}, size func() (w, h int, err error), change func(h, w int) error) {
	for {
		select {
		case <-done:
			return
		case <-ch:
			if w, h, err := size(); err == nil {
				_ = change(h, w)
			}
		}
	}
}
