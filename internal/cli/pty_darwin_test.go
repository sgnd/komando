package cli

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a new pseudo-terminal: the side a terminal window holds
// (master) and the one a program reads and writes as its terminal.
func openPTY() (master, tty *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(m.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		m.Close()
		return nil, nil, err
	}
	name := make([]byte, 128) // TIOCPTYGNAME fills a 128-byte buffer
	//lint:ignore SA1019 x/sys/unix has no wrapper for an ioctl that fills a buffer (its ioctlPtr is not exported)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); e != 0 {
		m.Close()
		return nil, nil, e
	}
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	t, err := os.OpenFile(string(name), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, t, nil
}
