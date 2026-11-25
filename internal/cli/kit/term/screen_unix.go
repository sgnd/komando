//go:build unix

package term

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	xterm "golang.org/x/term"
)

// screenSys is what a Unix screen keeps: the terminal's mode before raw
// mode, the signals it watches, and a pipe that wakes a wait.
type screenSys struct {
	fd    int
	saved *xterm.State
	sigs  chan os.Signal
	stop  chan struct{}
	wakeR *os.File // readable when the window changed size
	wakeW *os.File
}

// open turns raw mode and bracketed paste on and watches SIGWINCH (the
// window changed size), SIGTERM and SIGHUP. On SIGTERM or SIGHUP the
// terminal is put back first, then the process ends of that signal.
func (s *Screen) open() error {
	fd := int(s.in.Fd())
	if !xterm.IsTerminal(fd) || !VTOK {
		return ErrNoScreen
	}
	saved, err := xterm.MakeRaw(fd)
	if err != nil {
		return ErrNoScreen
	}
	r, w, err := os.Pipe()
	if err != nil {
		_ = xterm.Restore(fd, saved)
		return ErrNoScreen
	}
	s.sys = screenSys{fd: fd, saved: saved, sigs: make(chan os.Signal, 4), stop: make(chan struct{}), wakeR: r, wakeW: w}
	s.raw = true
	_, _ = io.WriteString(s.out, screenOn)
	watch := []os.Signal{syscall.SIGWINCH, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		watch = append(watch, syscall.SIGHUP)
	}
	signal.Notify(s.sys.sigs, watch...)
	go s.sys.watch(s)
	return nil
}

// watch handles the screen's signals until restore.
func (sys *screenSys) watch(s *Screen) {
	for {
		select {
		case <-sys.stop:
			return
		case sig := <-sys.sigs:
			if sig == syscall.SIGWINCH {
				_, _ = sys.wakeW.Write([]byte{1})
				continue
			}
			s.Restore()
			endOnSignal(sig)
		}
	}
}

// restore puts the saved mode back and stops watching signals. Called
// with s.mu held, once.
func (sys *screenSys) restore(s *Screen) {
	signal.Stop(sys.sigs)
	close(sys.stop)
	_ = xterm.Restore(sys.fd, sys.saved)
	_ = sys.wakeR.Close()
	_ = sys.wakeW.Close()
}

// wait waits until input is ready or the window changed size, for at
// most d (d < 0: no limit). Neither ready nor resized means the time ran
// out.
func (sys *screenSys) wait(s *Screen, d time.Duration) (ready, resized bool, err error) {
	ms := -1
	if d >= 0 {
		ms = int((d + time.Millisecond - 1) / time.Millisecond)
	}
	fds := []unix.PollFd{{Fd: int32(sys.fd), Events: unix.POLLIN}, {Fd: int32(sys.wakeR.Fd()), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(fds, ms)
		if errors.Is(err, unix.EINTR) {
			continue // a signal arrived; the watcher handles it
		}
		if err != nil {
			return false, false, err
		}
		break
	}
	if fds[1].Revents&unix.POLLIN != 0 {
		b := make([]byte, 64)
		_, _ = sys.wakeR.Read(b)
		return false, true, nil
	}
	if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
		return true, false, nil
	}
	return false, false, nil
}

// read reads what is waiting on the terminal.
func (sys *screenSys) read(s *Screen, buf []byte) (int, error) {
	for {
		n, err := unix.Read(sys.fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return max(n, 0), err
	}
}

// Size is the window's width and height; 0, 0 when it cannot be read.
func (s *Screen) Size() (w, h int) {
	w, h, err := xterm.GetSize(s.sys.fd)
	if err != nil {
		return 0, 0
	}
	return w, h
}

// stopJob stops the whole job, as any Ctrl-Z does; it returns when the
// job goes on (fg). Tests stand in for it: how a job stops depends on the
// process groups of the machine the tests run on.
var stopJob = func() { _ = unix.Kill(0, unix.SIGTSTP) }

// Suspend is Ctrl-Z: the terminal goes back to how it was, the process
// stops as a shell expects (SIGTSTP), and when it goes on (fg) raw mode
// and bracketed paste come back. The caller draws the screen again.
func (s *Screen) Suspend() error {
	s.mu.Lock()
	if !s.raw {
		s.mu.Unlock()
		return nil
	}
	_, _ = io.WriteString(s.out, screenOff)
	if err := xterm.Restore(s.sys.fd, s.sys.saved); err != nil {
		// never stop with the terminal still raw: end the screen instead
		s.mu.Unlock()
		s.Restore()
		return ErrNoScreen
	}
	s.mu.Unlock()

	stopJob()

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.raw {
		return nil
	}
	if _, err := xterm.MakeRaw(s.sys.fd); err != nil {
		s.raw = false
		signal.Stop(s.sys.sigs)
		close(s.sys.stop)
		_ = s.sys.wakeR.Close()
		_ = s.sys.wakeW.Close()
		return ErrNoScreen
	}
	_, _ = io.WriteString(s.out, screenOn)
	return nil
}
