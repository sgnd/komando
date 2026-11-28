// Package ftptest is an FTP and FTPS server for tests: one file, obj.txt,
// in /, or set listings by folder. Only tests import it.
package ftptest

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

// Server is a small FTP server for tests (FTPS when TLS is set). It keeps one
// file, obj.txt, in /. drop names a command (LIST, RETR, STOR, DELE, ...):
// the first time a session sends it, the server closes the control
// connection without a reply, like a dropped network path. reply550 makes
// that command answer 550 instead.
type Server struct {
	Ln       net.Listener
	Mu       sync.Mutex
	Logins   int
	Drop     string
	Dropped  bool
	Reply550 string
	File     []byte
	Exists   bool
	Dirs     map[string]string // LIST lines by folder, in place of obj.txt
	TLS      *tls.Config       // set: FTPS, explicit TLS on control and data
	CutData  string            // LIST only: its data connection closes before TLS is set up, then 226
	CutDir   string            // with CutData: only the listing of this folder is cut
}

func New(t *testing.T) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Ln: ln, File: []byte("old\n"), Exists: true}
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

func (s *Server) Target() driver.Target {
	return driver.Target{Address: s.Ln.Addr().String(), User: "u"}
}

func (s *Server) LoginCount() int {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Logins
}

// session is one control connection.
type session struct {
	s    *Server
	c    net.Conn
	r    *bufio.Reader
	data net.Listener
}

func (ss *session) say(f string, a ...any) { fmt.Fprintf(ss.c, f+"\r\n", a...) }

// listen opens a new data listener and returns its port.
func (ss *session) listen() int {
	if ss.data != nil {
		ss.data.Close()
	}
	ss.data, _ = net.Listen("tcp", "127.0.0.1:0")
	return ss.data.Addr().(*net.TCPAddr).Port
}

// accept opens the data connection for cmd; nil when the fake cut it.
func (ss *session) accept(cmd, arg string) (net.Conn, error) {
	s := ss.s
	dc, err := ss.data.Accept()
	if err != nil || s.TLS == nil {
		return dc, err
	}
	s.Mu.Lock()
	cut := cmd == s.CutData && (s.CutDir == "" || arg == s.CutDir)
	s.Mu.Unlock()
	if cut {
		dc.Close()
		return nil, nil
	}
	return tls.Server(dc, s.TLS), nil
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	ss := &session{s: s, c: c, r: bufio.NewReader(c)}
	ss.say("220 fake")
	for {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return
		}
		cmd, arg, _ := strings.Cut(strings.TrimSpace(line), " ")
		cmd = strings.ToUpper(cmd)
		s.Mu.Lock()
		drop := cmd == s.Drop && !s.Dropped
		if drop {
			s.Dropped = true
		}
		fail := cmd == s.Reply550
		s.Mu.Unlock()
		if drop {
			return // close without a reply: the client reads EOF
		}
		if fail {
			ss.say("550 refused")
			continue
		}
		if !ss.handle(cmd, arg) {
			return
		}
	}
}

// handle answers one command; false ends the session.
func (ss *session) handle(cmd, arg string) bool {
	s := ss.s
	switch cmd {
	case "USER":
		ss.say("331 password")
	case "PASS":
		s.Mu.Lock()
		s.Logins++
		s.Mu.Unlock()
		ss.say("230 in")
	case "FEAT":
		ss.say("211 no features")
	case "TYPE", "OPTS", "MKD", "PBSZ", "PROT":
		ss.say("200 ok")
	case "AUTH":
		if s.TLS == nil {
			ss.say("502 no TLS")
			return true
		}
		ss.say("234 go ahead")
		tc := tls.Server(ss.c, s.TLS)
		if tc.Handshake() != nil {
			return false
		}
		ss.c, ss.r = tc, bufio.NewReader(tc)
	case "EPSV":
		ss.say("229 ok (|||%d|)", ss.listen())
	case "PASV": // hands back the data listener's own address, 127.0.0.1
		p := ss.listen()
		ss.say("227 ok (127,0,0,1,%d,%d)", p>>8, p&0xff)
	case "LIST", "RETR", "STOR", "APPE":
		return ss.transfer(cmd, arg)
	case "QUIT":
		ss.say("221 bye")
		return false
	default:
		ss.file(cmd)
	}
	return true
}

// transfer runs a command with a data connection.
func (ss *session) transfer(cmd, arg string) bool {
	s := ss.s
	dc, err := ss.accept(cmd, arg)
	if err != nil {
		return false
	}
	ss.say("150 here")
	if dc == nil {
		ss.say("226 done")
		return true
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	switch cmd {
	case "LIST":
		if s.Dirs != nil {
			fmt.Fprint(dc, s.Dirs[arg])
		} else if s.Exists {
			fmt.Fprintf(dc, "-rw-r--r-- 1 u u %d Nov 07 12:00 obj.txt\r\n", len(s.File))
		}
	case "RETR":
		dc.Write(s.File)
	case "STOR":
		s.File, _ = io.ReadAll(dc)
	case "APPE":
		b, _ := io.ReadAll(dc)
		s.File = append(s.File, b...)
	}
	dc.Close()
	ss.say("226 done")
	return true
}

// file answers the commands on obj.txt that need no data connection.
func (ss *session) file(cmd string) {
	s := ss.s
	s.Mu.Lock()
	defer s.Mu.Unlock()
	switch cmd {
	case "SIZE":
		if !s.Exists {
			ss.say("550 no such file")
			return
		}
		ss.say("213 %d", len(s.File))
	case "RNFR":
		ss.say("350 ready")
	case "RNTO":
		s.Exists = true
		ss.say("250 renamed")
	case "DELE":
		if !s.Exists {
			ss.say("550 no such file")
			return
		}
		s.Exists = false
		ss.say("250 deleted")
	default:
		ss.say("502 not here")
	}
}
