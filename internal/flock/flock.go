// Package flock takes and releases an exclusive lock on an open file, so
// komando processes running at the same time wait for each other. On Unix
// it is flock(2); on Windows it is LockFileEx.
package flock
