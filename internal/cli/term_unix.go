//go:build !windows

package cli

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

// consoleVT: a Unix terminal reads escape sequences as they are.
func consoleVT(int) (ok bool, restore func()) { return true, func() {} }
