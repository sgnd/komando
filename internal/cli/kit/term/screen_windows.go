//go:build windows

package term

import "time"

// screenSys is empty on Windows: the screen is not built for the Windows
// console yet (its input has no wait that ignores focus and mouse events
// without more console code), so OpenScreen says ErrNoScreen and komando
// asks in lines, as today.
type screenSys struct{}

func (s *Screen) open() error { return ErrNoScreen }

func (sys *screenSys) restore(*Screen) {}

func (sys *screenSys) wait(*Screen, time.Duration) (bool, bool, error) {
	return false, false, ErrNoScreen
}

func (sys *screenSys) read(*Screen, []byte) (int, error) { return 0, ErrNoScreen }

// Size is 0, 0: there is no screen on Windows yet.
func (s *Screen) Size() (w, h int) { return 0, 0 }

// Suspend does nothing: a Windows console has no Ctrl-Z job control.
func (s *Screen) Suspend() error { return nil }
