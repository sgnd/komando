//go:build windows

package cli

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The console calls golang.org/x/sys/windows does not wrap.
var (
	procPeekConsoleInputW = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekConsoleInputW")
	procReadConsoleInputW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")
)

// dropNoKeys reads away the console events it peeked when none of them
// is a typed character. Only those: a key pressed meanwhile stays.
func dropNoKeys(h windows.Handle) {
	var total uint32
	if err := windows.GetNumberOfConsoleInputEvents(h, &total); err != nil || total == 0 {
		return
	}
	recs := make([]inputRecord, total)
	var got uint32
	if r, _, _ := procPeekConsoleInputW.Call(uintptr(h), uintptr(unsafe.Pointer(&recs[0])), uintptr(total), uintptr(unsafe.Pointer(&got))); r == 0 || got == 0 {
		return
	}
	for _, e := range recs[:got] {
		if e.eventType == keyEvent && e.keyDown != 0 && e.char != 0 {
			return
		}
	}
	var read uint32
	procReadConsoleInputW.Call(uintptr(h), uintptr(unsafe.Pointer(&recs[0])), uintptr(got), uintptr(unsafe.Pointer(&read)))
}

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

// errWaitInterrupted is never returned on Windows; it keeps callers alike.
var errWaitInterrupted = errors.New("wait interrupted")

// waitInput waits up to ms milliseconds for a typed character on the
// console fd and says whether one is there to read. The console handle is
// signalled by any event (a key release, focus, the mouse), so events that
// carry no character are thrown away and the wait goes on.
func waitInput(fd, ms int) (bool, error) {
	h := windows.Handle(fd)
	deadline := time.Now().Add(time.Duration(ms) * time.Millisecond)
	for {
		left := time.Until(deadline)
		if left < 0 {
			left = 0
		}
		ev, err := windows.WaitForSingleObject(h, uint32(left/time.Millisecond))
		if err != nil {
			return false, err
		}
		if ev != windows.WAIT_OBJECT_0 {
			return false, nil
		}
		if typedAhead(fd) > 0 {
			return true, nil
		}
		dropNoKeys(h)
		if left == 0 {
			return false, nil
		}
		time.Sleep(time.Millisecond)
	}
}
