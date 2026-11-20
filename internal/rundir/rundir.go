// Package rundir finds komando's own per-user folder for short-lived
// private files (a restore's checked copy), never the shared temp folder,
// where another user may have planted a name or a link.
package rundir

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Base is where the folder goes; tests point it elsewhere.
//   - Linux and BSD: $XDG_RUNTIME_DIR/komando when that folder is this
//     user's and 0700, else $XDG_STATE_HOME/komando/run
//     (~/.local/state/komando/run);
//   - macOS: ~/Library/Application Support/komando/run;
//   - Windows: %LOCALAPPDATA%\komando\run.
var Base = func() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "komando", "run"), nil
	case "windows":
		d := os.Getenv("LOCALAPPDATA")
		if d == "" {
			return "", errors.New("LOCALAPPDATA is not set")
		}
		return filepath.Join(d, "komando", "run"), nil
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) && Check(x) == nil {
		return filepath.Join(x, "komando"), nil
	}
	state := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(state) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "komando", "run"), nil
}

// Dir returns the folder, made 0700 when missing, after Check: a link, a
// file, another user's folder or one others may open is refused.
func Dir() (string, error) {
	d, err := Base()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	if err := Check(d); err != nil {
		return "", err
	}
	return d, nil
}

// Stale is the age of a leftover Sweep removes: a run that was killed
// outright (SIGKILL, a power cut) could not remove its own.
const Stale = 10 * time.Minute

// Create makes a new file NAME-<random>.tmp in dir: O_EXCL (an existing
// name or link is never opened) and mode 0600.
func Create(dir, name string) (*os.File, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return create(filepath.Join(dir, name+"-"+hex.EncodeToString(b)+".tmp"))
}

func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

// Sweep removes NAME-*.tmp leftovers older than Stale from dir, a folder
// Dir checked (only this user can write there). Links are removed, never
// followed. A file another run still reads goes too: it reads through its
// open descriptor, which keeps the bytes until it closes it.
func Sweep(dir, name string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, name+"-") || !strings.HasSuffix(n, ".tmp") || e.IsDir() {
			continue
		}
		p := filepath.Join(dir, n)
		if fi, err := os.Lstat(p); err == nil && time.Since(fi.ModTime()) > Stale {
			_ = os.Remove(p)
		}
	}
}
