package flock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLockWaits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.OpenFile(p, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := Lock(a); err != nil {
		t.Fatal(err)
	}
	got, done := make(chan struct{}), make(chan struct{})
	go func() { _ = Lock(b); close(got); _ = Unlock(b); close(done) }()
	defer func() { <-done }()
	select {
	case <-got:
		t.Fatal("second lock did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	if err := Unlock(a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never got the file")
	}
}
