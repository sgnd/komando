//go:build windows

package cli

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// The console calls golang.org/x/sys/windows does not wrap.
var (
	procPeekConsoleInputW = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekConsoleInputW")
)

// inputRecord is the console's INPUT_RECORD with its KEY_EVENT_RECORD.
type inputRecord struct {
	eventType   uint16
	_           uint16
	keyDown     int32
	repeatCount uint16
	keyCode     uint16
	scanCode    uint16
	char        uint16
	controlKeys uint32
}

const keyEvent = 0x0001

// typedAhead is how many typed characters wait unread on the console fd.
// Key releases, focus and mouse events do not count: a read would wait
// for a key all the same.
func typedAhead(fd int) int {
	h := windows.Handle(fd)
	var total uint32
	if err := windows.GetNumberOfConsoleInputEvents(h, &total); err != nil || total == 0 {
		return 0
	}
	recs := make([]inputRecord, total)
	var got uint32
	r, _, _ := procPeekConsoleInputW.Call(uintptr(h), uintptr(unsafe.Pointer(&recs[0])), uintptr(total), uintptr(unsafe.Pointer(&got)))
	if r == 0 {
		return 0
	}
	n := 0
	for _, e := range recs[:got] {
		if e.eventType == keyEvent && e.keyDown != 0 && e.char != 0 {
			n += max(int(e.repeatCount), 1)
		}
	}
	return n
}

// dropTypedAhead throws away what waits unread on the console fd.
func dropTypedAhead(fd int) error { return windows.FlushConsoleInputBuffer(windows.Handle(fd)) }

// readTTY reads what waits on the console fd into b.
func readTTY(fd int, b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(windows.Handle(fd), b, &n, nil)
	return int(n), err
}

// echoOff stops the console from showing what is typed on fd.
func echoOff(fd int) error {
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return err
	}
	return windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
}

// consoleVT turns on escape sequences (colour, clearing a line) for the
// console on fd: a Windows console shows them as text unless a program
// asks. It says whether they work, and gives what puts the console back.
func consoleVT(fd int) (ok bool, restore func()) {
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
