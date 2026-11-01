package sshx

import (
	"net"
	"testing"
	"time"
)

func TestWithDeadlinesClosesOnExpiry(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := WithDeadlines(a)
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read returned without error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadline did not interrupt the read")
	}
	// clearing a deadline keeps the connection open
	x, y := net.Pipe()
	defer y.Close()
	d := WithDeadlines(x)
	d.SetDeadline(time.Now().Add(20 * time.Millisecond))
	d.SetDeadline(time.Time{})
	time.Sleep(60 * time.Millisecond)
	go y.Write([]byte("k"))
	if _, err := d.Read(make([]byte, 1)); err != nil {
		t.Fatalf("cleared deadline still closed the conn: %v", err)
	}
}
