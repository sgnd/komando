//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

// detachAttr makes a child process outlive this command and its terminal.
func detachAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

// withUmask runs fn with the process umask set to mask, so files fn
// creates (a socket) are never readable by others even for a moment.
func withUmask(mask int, fn func()) {
	old := syscall.Umask(mask)
	defer syscall.Umask(old)
	fn()
}

// notifyResize sends on ch whenever the terminal fd changes size, until
// the returned stop is called.
func notifyResize(_ int, ch chan os.Signal) (stop func()) {
	signal.Notify(ch, syscall.SIGWINCH)
	return func() { signal.Stop(ch) }
}

// alive reports whether pid is a process this user may signal.
func alive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

// fileOwner is the user and group that own fi.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// fileLinks is how many names (hard links) the file p, stat'ed as fi, has.
func fileLinks(_ string, fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// exeSuffix ends the name of a program file.
const exeSuffix = ""

// swapExe puts the new program tmp where exe is. A rename is atomic, and a
// komando running now keeps the old file.
func swapExe(tmp, exe string) error { return os.Rename(tmp, exe) }
