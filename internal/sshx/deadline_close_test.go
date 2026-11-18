package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hopServer is an SSH server in this process whose direct-tcpip channels
// send one line and close at once, as the far end of a hop does when the
// server behind it closes its socket (an FTP data connection after 226).
func hopServer(t *testing.T) *ssh.Client { t.Helper(); return hopServerKeep(t, false) }

// hopServerKeep is hopServer; with keep, its channels stay open.
func hopServerKeep(t *testing.T, keep bool) *ssh.Client {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		a, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(a, cfg)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(creqs)
			ch.Write([]byte("226\n"))
			if !keep {
				ch.Close()
			}
		}
	}()
	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(b, "hop", &ssh.ClientConfig{
		User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { c.Close() })
	return c
}

// hopOpen is a channel through a hop whose far end keeps it open.
func hopOpen(t *testing.T) net.Conn {
	t.Helper()
	c, err := hopServerKeep(t, true).Dial("tcp", "db:5432")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Closing a hop connection whose far end closed it first is no error.
// x/crypto/ssh answers the far end's close itself, and then reports a
// second close as io.EOF; through TLS and the FTP client that became
// "the server: EOF" after a transfer that had worked.
func TestWithDeadlinesCloseAfterTheFarEndClosed(t *testing.T) {
	raw, err := hopServer(t).Dial("tcp", "ftps:30004")
	if err != nil {
		t.Fatal(err)
	}
	c := WithDeadlines(raw)
	if _, err := io.ReadAll(c); err != nil {
		t.Fatal(err)
	}
	// wait until the far end's close is handled: a write then says EOF
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := c.Write([]byte("x")); err == io.EOF {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the far end's close never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close after the far end closed: %v", err)
	}
}

// A Close on a channel that is still open closes it, as before: the far
// end sees it.
func TestWithDeadlinesCloseAnOpenChannel(t *testing.T) {
	c := WithDeadlines(hopOpen(t))
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Error("a write after Close worked")
	}
}

// Any other error from Close is still returned, and io.EOF from Read or
// Write is untouched.
func TestWithDeadlinesKeepsOtherErrors(t *testing.T) {
	boom := errors.New("boom")
	c := WithDeadlines(errConn{closeErr: boom})
	if err := c.Close(); err != boom {
		t.Errorf("Close: %v, want boom", err)
	}
	c = WithDeadlines(errConn{closeErr: io.EOF})
	if _, err := c.Read(nil); err != io.EOF {
		t.Errorf("Read: %v, want io.EOF", err)
	}
	if _, err := c.Write(nil); err != io.EOF {
		t.Errorf("Write: %v, want io.EOF", err)
	}
}

// errConn fails every call: Read and Write with io.EOF, Close with closeErr.
type errConn struct {
	net.Conn
	closeErr error
}

func (e errConn) Read([]byte) (int, error)  { return 0, io.EOF }
func (e errConn) Write([]byte) (int, error) { return 0, io.EOF }
func (e errConn) Close() error              { return e.closeErr }
