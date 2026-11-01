package sshx

import (
	"net"
	"sync"
	"time"
)

// SSH channels do not support deadlines, but database and cache clients use
// them for timeouts. WithDeadlines emulates them: when a deadline passes the
// connection is closed, which ends any blocked read or write.
func WithDeadlines(c net.Conn) net.Conn { return &deadlineConn{Conn: c} }

type deadlineConn struct {
	net.Conn
	mu    sync.Mutex
	timer *time.Timer
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	c.timer = time.AfterFunc(time.Until(t), func() { c.Conn.Close() })
	return nil
}

// Read and write deadlines share one timer: the connection is closed when
// the earliest one passes, which is all a short-lived CLI connection needs.
func (c *deadlineConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *deadlineConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}
