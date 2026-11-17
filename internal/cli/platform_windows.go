//go:build windows

package cli

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/netx"
)

// detachAttr makes a child process outlive this command and its console:
// it gets no console of its own and its own process group, so Ctrl+C in
// this window does not reach it.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
}

// withUmask runs fn. Windows has no umask: a new file gets the ACL of its
// folder, and the callers chmod/limit access themselves.
func withUmask(_ int, fn func()) { fn() }

// notifyResize sends on ch whenever the console fd changes size, until the
// returned stop is called. Windows has no SIGWINCH, so the size is polled.
func notifyResize(fd int, ch chan os.Signal) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		w0, h0, _ := term.GetSize(fd)
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			w, h, err := term.GetSize(fd)
			if err != nil || (w == w0 && h == h0) {
				continue
			}
			w0, h0 = w, h
			select {
			case ch <- syscall.Signal(0): // not Ctrl+C: the receiver only reads the new size
			default:
			}
		}
	}()
	return func() { close(done) }
}

// alive reports whether pid is a running process.
func alive(pid int) bool { return netx.Alive(pid) }

// fileOwner reports no owner: Windows files have an owner SID, not a uid.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

// fileLinks is how many names (hard links) the file p has.
func fileLinks(p string, _ os.FileInfo) uint64 {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0
	}
	return uint64(info.NumberOfLinks)
}

// exeSuffix ends the name of a program file.
const exeSuffix = ".exe"

// swapExe puts the new program tmp where exe is. Windows does not let a
// running program's file be replaced, but it may be renamed: exe moves
// aside to exe.old, tmp takes its name, and exe.old is removed when no
// komando runs it any more (here, or at the next update). A failed second
// rename puts exe back.
func swapExe(tmp, exe string) error {
	old := exe + ".old"
	_ = os.Remove(old) // left by an earlier update
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Rename(old, exe)
		return err
	}
	_ = os.Remove(old) // fails while this komando runs from it
	return nil
}

// noCoreDumps: Windows writes no core file of its own (a crash dump needs
// Windows Error Reporting set up for it).
func noCoreDumps() {}

// raise: Windows has no signal to end a process with; the caller exits.
func raise(os.Signal) {}
