//go:build windows

package term

import "golang.org/x/sys/windows"

// ConsoleVT turns on escape sequences (colour, clearing a line) for the
// console on fd: a Windows console shows them as text unless a program
// asks. It says whether they work, and gives what puts the console back.
func ConsoleVT(fd int) (ok bool, restore func()) {
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false, func() {} // not a console: a pipe or a file
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true, func() {}
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false, func() {} // a console older than Windows 10
	}
	return true, func() { _ = windows.SetConsoleMode(h, mode) }
}
