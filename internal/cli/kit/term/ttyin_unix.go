//go:build unix

// komando is released for linux, darwin and windows, on amd64 and arm64
// (PLATFORMS in the Makefile; release.yml signs the darwin ones). Of the
// unix systems, only darwin and linux define the termios ioctls and
// TypedAhead (ttyin_darwin.go, ttyin_linux.go), so this file builds for
// those two; `make bins` builds every release target.

package term

import "golang.org/x/sys/unix"

// readTTY reads what waits on the terminal fd into b.
func readTTY(fd int, b []byte) (int, error) { return unix.Read(fd, b) }

// echoOff stops the terminal from showing what is typed on fd.
func echoOff(fd int) error {
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(fd, ioctlSetTermios, t)
}
