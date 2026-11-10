//go:build !darwin

package sealdb

import "os"

func fullSync(f *os.File) error { return f.Sync() }
