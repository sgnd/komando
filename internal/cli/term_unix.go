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

// errWaitInterrupted is waitInput's error when a signal cut the wait short.
var errWaitInterrupted = unix.EINTR

// waitInput waits up to ms milliseconds for input on fd and says whether
// some is there to read.
func waitInput(fd, ms int) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, ms)
	return n > 0, err
}
