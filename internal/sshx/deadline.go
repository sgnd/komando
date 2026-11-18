package sshx

import (
	"io"
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

// Close closes the channel. It swallows one error only: the bare io.EOF
// x/crypto/ssh returns when the channel has already sent its close. That
// happens when the far end closed first (the server behind the hop closed
// its socket): the library answers that close itself and marks the channel
// closed (golang.org/x/crypto v0.59.0 ssh/channel.go:458-461, close() at
// :414-428), and writePacket then reports any later close as io.EOF
// (:231-236). The channel is closed either way. Passed on, TLS and the FTP
// client turned a transfer that worked into "the server: EOF" (C132). Any
// other error from Close is returned; io.EOF from Read or Write stays an
// error; CloseWrite sends EOF, not close, so a Close after it is unchanged.
func (c *deadlineConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	if err := c.Conn.Close(); err != io.EOF {
		return err
	}
	return nil
}
