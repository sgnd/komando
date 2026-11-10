//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// authPipe hands the VPN login to openvpn (run as root) through a named
// pipe in dir, readable by this user only: the password never lies in a
// file on disk, as an --auth-user-pass file would. The login is written
// once, when openvpn opens the pipe. done removes the pipe; if openvpn
// never opened it (sudo refused), done does not wait for it.
func authPipe(dir, name, content string) (path string, done func(), err error) {
	// in a new folder of its own (0700): no other process of this user can
	// put a link in its place between its making and openvpn opening it
	pdir, err := os.MkdirTemp(dir, ".auth-")
	if err != nil {
		return "", nil, err
	}
	path = filepath.Join(pdir, name+".auth")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		os.Remove(pdir)
		return "", nil, err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := os.OpenFile(path, os.O_WRONLY, 0) // waits for the reader
		if err != nil {
			return
		}
		_, _ = f.WriteString(content)
		f.Close()
	}()
	var once sync.Once
	done = func() {
		once.Do(func() {
			// a reader of our own lets a writer still waiting go
			if r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
				ch := make(chan struct{})
				go func() { wg.Wait(); close(ch) }()
				select {
				case <-ch:
				case <-time.After(2 * time.Second):
				}
				r.Close()
			}
			os.RemoveAll(pdir)
		})
	}
	return path, done, nil
}
