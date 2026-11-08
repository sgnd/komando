package cli

import "golang.org/x/sys/unix"

// The ioctls that read and set a terminal's settings (termios).
const ioctlGetTermios, ioctlSetTermios = unix.TCGETS, unix.TCSETS

// typedAhead is how many bytes wait unread on the terminal fd.
func typedAhead(fd int) int {
	n, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
	if err != nil {
		return 0
	}
	return n
}

// dropTypedAhead throws away what waits unread on the terminal fd.
func dropTypedAhead(fd int) error {
	return unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
