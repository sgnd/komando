package term

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// A Screen is one raw-mode session on a person's terminal, for the
// interactive mode (C162, design note 2026-11-25 section 3.6). It is the
// only place that turns raw mode on for it, and the only place that puts
// the terminal back: Restore runs on every way out (a key, an error, an
// idle screen, a window made too small, SIGTERM, SIGHUP, Ctrl-Z) and a
// caller defers it for a panic. Restore can run any number of times.
//
// Reads are made only when input is waiting, so nothing is left reading
// the terminal after Restore: the question a command asks next gets every
// key typed after the screen closed.

// ScreenOptions are the limits of a screen.
type ScreenOptions struct {
	MinWidth, MinHeight int           // a smaller window ends the screen (ErrTooSmall)
	Idle                time.Duration // no key for this long ends it (ErrIdle); 0 means never
}

var (
	// ErrNoScreen: this terminal cannot carry the screen; ask in lines.
	ErrNoScreen = errors.New("this terminal cannot show the interactive screen")
	// ErrTooSmall: the window is smaller than the screen needs; ask in lines.
	ErrTooSmall = errors.New("the window is too small for the interactive screen")
	// ErrIdle: nobody pressed a key for ScreenOptions.Idle.
	ErrIdle = errors.New("no key was pressed for a long time")
)

// EscWait is how long a lone ESC waits for the rest of a sequence before
// it counts as the Esc key. A terminal sends a whole sequence at once, so
// this is far longer than one takes, and short enough not to be felt.
const EscWait = 50 * time.Millisecond

// PasteWait is how long a paste that has not ended waits for more of it
// (a long paste over a slow link comes in parts); after that it ends.
const PasteWait = time.Second

// screenOn turns on what the screen needs from the terminal beyond raw
// mode: bracketed paste. screenOff turns it off, resets colours and
// attributes and shows the cursor again.
const (
	screenOn  = "\x1b[?2004h"
	screenOff = "\x1b[?2004l\x1b[0m\x1b[?25h"
)

// Screen is a terminal in raw mode for the interactive screen.
type Screen struct {
	in  *os.File
	out io.Writer
	opt ScreenOptions
	dec decoder
	sys screenSys // what the platform keeps: the saved state, signals

	mu  sync.Mutex
	raw bool // raw mode is on now
}

// OpenScreen puts in into raw mode for the screen and turns bracketed
// paste on, drawing on out. ErrNoScreen says this terminal cannot carry
// it, ErrTooSmall that the window is smaller than opt asks; both leave the
// terminal as it was.
func OpenScreen(in *os.File, out io.Writer, opt ScreenOptions) (*Screen, error) {
	s := &Screen{in: in, out: out, opt: opt}
	if err := s.open(); err != nil {
		return nil, err
	}
	if w, h := s.Size(); !s.fits(w, h) {
		s.Restore()
		return nil, ErrTooSmall
	}
	return s, nil
}

// fits says whether a window of w by h holds the screen.
func (s *Screen) fits(w, h int) bool { return w >= s.opt.MinWidth && h >= s.opt.MinHeight }

// Write draws on the screen's output.
func (s *Screen) Write(p []byte) (int, error) { return s.out.Write(p) }

// Restore puts the terminal back as it was before OpenScreen: bracketed
// paste off, colours reset, cursor shown, the saved mode back, the signal
// handlers gone. It does nothing the second time.
func (s *Screen) Restore() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.raw {
		return
	}
	s.raw = false
	_, _ = io.WriteString(s.out, screenOff)
	s.sys.restore(s)
}

// ReadKey waits for the next key. A window that changed size and still
// fits gives KeyResize. Any error restores the terminal first: ErrIdle,
// ErrTooSmall, io.EOF (the terminal closed) or a read error.
func (s *Screen) ReadKey() (Key, error) {
	last := time.Now()
	for {
		if k, ok := s.dec.next(false); ok {
			if k.Kind != KeyNone {
				return k, nil
			}
			continue
		}
		// the decoder needs input: the rest of a key, or a new one
		wait := time.Duration(-1) // no limit
		if s.dec.pending() {
			wait = EscWait
			if s.dec.pasting {
				wait = PasteWait
			}
		}
		if s.opt.Idle > 0 {
			left := s.opt.Idle - time.Since(last)
			if left <= 0 {
				s.Restore()
				return Key{}, ErrIdle
			}
			if wait < 0 || left < wait {
				wait = left
			}
		}
		ready, resized, err := s.sys.wait(s, wait)
		switch {
		case err != nil:
			s.Restore()
			return Key{}, err
		case resized:
			if w, h := s.Size(); !s.fits(w, h) {
				s.Restore()
				return Key{}, ErrTooSmall
			}
			return Key{Kind: KeyResize}, nil
		case ready:
			buf := make([]byte, FieldMax)
			n, err := s.sys.read(s, buf)
			if n == 0 && err == nil {
				err = io.EOF
			}
			if err != nil {
				s.Restore()
				return Key{}, err
			}
			s.dec.add(buf[:n])
			last = time.Now()
		case s.dec.pending():
			// the rest did not come in time: decide with what is there
			if k, ok := s.dec.next(true); ok && k.Kind != KeyNone {
				return k, nil
			}
		}
	}
}
