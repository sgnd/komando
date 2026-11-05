package cli

import "golang.org/x/sys/unix"

// fionread is FIONREAD (_IOR('f', 127, int)): bytes waiting to be read.
const fionread = 0x4004667f

// typedAhead is how many bytes wait unread on the terminal fd.
func typedAhead(fd int) int {
	n, err := unix.IoctlGetInt(fd, fionread)
	if err != nil {
		return 0
	}
	return n
}

// dropTypedAhead throws away what waits unread on the terminal fd.
func dropTypedAhead(fd int) error {
	return unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, 1) // FREAD
}
