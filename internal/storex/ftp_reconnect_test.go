package storex

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// fakeFTP is a small plain-FTP server for the reconnect tests. It keeps one
// file, obj.txt, in /. drop names a command (LIST, RETR, STOR, DELE, ...):
// the first time a session sends it, the server closes the control
// connection without a reply, like a dropped network path. reply550 makes
// that command answer 550 instead.
type fakeFTP struct {
	ln       net.Listener
	mu       sync.Mutex
	logins   int
	drop     string
	dropped  bool
	reply550 string
	file     []byte
	exists   bool
}

func newFakeFTP(t *testing.T) *fakeFTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeFTP{ln: ln, file: []byte("old\n"), exists: true}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeFTP) target() driver.Target {
	return driver.Target{Address: s.ln.Addr().String(), User: "u"}
}

func (s *fakeFTP) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

func (s *fakeFTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(f string, a ...any) { fmt.Fprintf(c, f+"\r\n", a...) }
	say("220 fake")
	var data net.Listener
	var rnfr string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		cmd = strings.ToUpper(cmd)
		s.mu.Lock()
		drop := cmd == s.drop && !s.dropped
		if drop {
			s.dropped = true
		}
		fail := cmd == s.reply550
		s.mu.Unlock()
		if drop {
			return // close without a reply: the client reads EOF
		}
		if fail {
			say("550 refused")
			continue
		}
		switch cmd {
		case "USER":
			say("331 password")
		case "PASS":
			s.mu.Lock()
			s.logins++
			s.mu.Unlock()
			say("230 in")
		case "FEAT":
			say("211 no features")
		case "TYPE", "OPTS", "MKD":
			say("200 ok")
		case "EPSV":
			if data != nil {
				data.Close()
			}
			data, _ = net.Listen("tcp", "127.0.0.1:0")
			say("229 ok (|||%d|)", data.Addr().(*net.TCPAddr).Port)
		case "LIST":
			dc, err := data.Accept()
			if err != nil {
				return
			}
			say("150 here")
			s.mu.Lock()
			if s.exists {
				fmt.Fprintf(dc, "-rw-r--r-- 1 u u %d Nov 07 12:00 obj.txt\r\n", len(s.file))
			}
			s.mu.Unlock()
			dc.Close()
			say("226 done")
		case "RETR":
			dc, err := data.Accept()
			if err != nil {
				return
			}
			say("150 here")
			s.mu.Lock()
			dc.Write(s.file)
			s.mu.Unlock()
			dc.Close()
			say("226 done")
		case "STOR":
			dc, err := data.Accept()
			if err != nil {
				return
			}
			say("150 send")
			b, _ := io.ReadAll(dc)
			dc.Close()
			s.mu.Lock()
			s.file = b
			s.mu.Unlock()
			say("226 stored")
		case "SIZE":
			s.mu.Lock()
			ok := s.exists
			n := len(s.file)
			s.mu.Unlock()
			if !ok {
				say("550 no such file")
				continue
			}
			say("213 %d", n)
		case "RNFR":
			rnfr = arg
			say("350 ready")
		case "RNTO":
			_ = rnfr
			s.mu.Lock()
			s.exists = true
			s.mu.Unlock()
			say("250 renamed")
		case "DELE":
			s.mu.Lock()
			ok := s.exists
			s.exists = false
			s.mu.Unlock()
			if !ok {
				say("550 no such file")
				continue
			}
			say("250 deleted")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 not here")
		}
	}
}

func openFake(t *testing.T, s *fakeFTP) Bucket {
	t.Helper()
	b, err := OpenFTP(context.Background(), s.target(), "p", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func errCode(err error) string {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe.Code
	}
	return fmt.Sprint(err)
}

func TestFTPReconnectsOnceAfterADroppedConnection(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		s := newFakeFTP(t)
		s.drop = "LIST"
		b := openFake(t, s)
		objs, _, err := b.List(context.Background(), "", recursive, 0)
		if err != nil {
			t.Fatalf("recursive=%v: List after a drop: %v", recursive, err)
		}
		if len(objs) != 1 || objs[0].Key != "obj.txt" {
			t.Fatalf("recursive=%v: List = %+v", recursive, objs)
		}
		if got := s.loginCount(); got != 2 {
			t.Fatalf("recursive=%v: %d logins, want 2 (one new session)", recursive, got)
		}
	}
}

func TestFTPDoesNotRepeatAfterAnFTPError(t *testing.T) {
	s := newFakeFTP(t)
	s.reply550 = "LIST"
	b := openFake(t, s)
	if _, _, err := b.List(context.Background(), "", false, 0); err == nil {
		t.Fatal("List with a 550 reply: no error")
	}
	if got := s.loginCount(); got != 1 {
		t.Fatalf("%d logins after an FTP error reply, want 1 (no new session)", got)
	}
}

func TestFTPGetRepeatsOnlyBeforeAnyByte(t *testing.T) {
	s := newFakeFTP(t)
	s.drop = "RETR"
	b := openFake(t, s)
	var w bytes.Buffer
	n, err := b.Get(context.Background(), "obj.txt", &w)
	if err != nil || n != 4 || w.String() != "old\n" {
		t.Fatalf("Get after a drop before the data: n=%d %q err=%v", n, w.String(), err)
	}
	if got := s.loginCount(); got != 2 {
		t.Fatalf("%d logins, want 2", got)
	}
}

// onlyReader hides the Seek of a bytes.Reader: a source that cannot start over.
type onlyReader struct{ io.Reader }

func TestFTPPutRepeatsOnlyWhenTheSourceCanStartOver(t *testing.T) {
	s := newFakeFTP(t)
	s.drop = "STOR"
	b := openFake(t, s)
	err := b.Put(context.Background(), "obj.txt", onlyReader{strings.NewReader("new\n")}, 4, "")
	if errCode(err) != "STORAGE_CONNECT" {
		t.Fatalf("Put from a pipe after a drop: %v, want STORAGE_CONNECT", err)
	}
	if got := s.loginCount(); got != 1 {
		t.Fatalf("%d logins for a source that cannot start over, want 1", got)
	}

	s2 := newFakeFTP(t)
	s2.drop = "STOR"
	b2 := openFake(t, s2)
	if err := b2.Put(context.Background(), "obj.txt", bytes.NewReader([]byte("new\n")), 4, ""); err != nil {
		t.Fatalf("Put from a file after a drop: %v", err)
	}
	s2.mu.Lock()
	got := string(s2.file)
	s2.mu.Unlock()
	if got != "new\n" {
		t.Fatalf("server has %q after the repeated upload, want the whole new file", got)
	}
	if n := s2.loginCount(); n != 2 {
		t.Fatalf("%d logins, want 2", n)
	}
}

func TestFTPRemoveCountsAFirstTryThatWorked(t *testing.T) {
	s := newFakeFTP(t)
	s.drop = "DELE"
	// the drop happens before the server deletes; remove it by hand to act
	// like a reply lost after the file was gone
	s.exists = false
	b := openFake(t, s)
	if err := b.Remove(context.Background(), "obj.txt"); err != nil {
		t.Fatalf("Remove whose repeat finds no file: %v, want nil", err)
	}
	if got := s.loginCount(); got != 2 {
		t.Fatalf("%d logins, want 2", got)
	}
}
