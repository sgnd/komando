//go:build !windows

package store

import (
	"errors"
	"os"
)

// syncDir flushes a folder's entries (a rename in it) to disk.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
