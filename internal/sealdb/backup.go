package sealdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Backup writes a consistent copy of the store to dst, which must not
// exist. A plain copy of the file taken during a write may be broken.
func (d *DB) Backup(ctx context.Context, dst string) error {
	release, err := d.enter()
	if err != nil {
		return err
	}
	defer release()
	if err := d.stopped(false); err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("sealdb: %s already exists", dst)
	}
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	// VACUUM INTO refuses a non-empty file; an empty one made with 0600
	// keeps the copy private
	uri, err := fileURI(dst, nil)
	if err == nil {
		_, err = d.db.ExecContext(ctx, `VACUUM INTO ?`, uri)
	}
	if err == nil {
		err = syncFile(dst)
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// syncOpened flushes one opened file or folder (tests watch it).
var syncOpened = fullSync

// syncFile flushes path and its folder to disk; VACUUM INTO does not take
// the store's sync settings.
func syncFile(path string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		// the file opened for writing: Windows flushes no file opened to read
		flag := os.O_RDWR
		if p != path {
			flag = os.O_RDONLY
		}
		f, err := os.OpenFile(p, flag, 0)
		if err != nil {
			return err
		}
		err = syncOpened(f)
		f.Close()
		// a folder cannot be synced on some systems (Windows)
		if err != nil && p == path {
			return err
		}
	}
	return nil
}
