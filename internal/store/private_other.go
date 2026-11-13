//go:build !windows

package store

// privateHome does nothing here: the folder's mode, 0700, keeps it private.
func privateHome(string) error { return nil }
