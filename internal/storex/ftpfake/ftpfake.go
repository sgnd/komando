// Package ftpfake is an FTP and FTPS server for tests: one file, obj.txt,
// in /, or set listings by folder. Only tests import it.
package ftpfake

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

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(f string, a ...any) { fmt.Fprintf(c, f+"\r\n", a...) }
	say("220 fake")
	var data net.Listener
	var rnfr string
	// accept opens the data connection for cmd; nil when the fake cut it
	accept := func(cmd, arg string) (net.Conn, error) {
		dc, err := data.Accept()
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
	for {
		line, err := r.ReadString('\n')
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
			say("550 refused")
			continue
		}
		switch cmd {
		case "USER":
			say("331 password")
		case "PASS":
			s.Mu.Lock()
			s.Logins++
			s.Mu.Unlock()
			say("230 in")
		case "FEAT":
			say("211 no features")
		case "TYPE", "OPTS", "MKD", "PBSZ", "PROT":
			say("200 ok")
		case "AUTH":
			if s.TLS == nil {
				say("502 no TLS")
				continue
			}
			say("234 go ahead")
			tc := tls.Server(c, s.TLS)
			if tc.Handshake() != nil {
				return
			}
			c, r = tc, bufio.NewReader(tc)
		case "EPSV":
			if data != nil {
				data.Close()
			}
			data, _ = net.Listen("tcp", "127.0.0.1:0")
			say("229 ok (|||%d|)", data.Addr().(*net.TCPAddr).Port)
		case "LIST":
			dc, err := accept(cmd, arg)
			if err != nil {
				return
			}
			say("150 here")
			if dc == nil {
				say("226 done")
				continue
			}
			s.Mu.Lock()
			if s.Dirs != nil {
				fmt.Fprint(dc, s.Dirs[arg])
			} else if s.Exists {
				fmt.Fprintf(dc, "-rw-r--r-- 1 u u %d Nov 07 12:00 obj.txt\r\n", len(s.File))
			}
			s.Mu.Unlock()
			dc.Close()
			say("226 done")
		case "RETR":
			dc, err := accept(cmd, arg)
			if err != nil {
				return
			}
			say("150 here")
			s.Mu.Lock()
			dc.Write(s.File)
			s.Mu.Unlock()
			dc.Close()
			say("226 done")
		case "STOR":
			dc, err := accept(cmd, arg)
			if err != nil {
				return
			}
			say("150 send")
			b, _ := io.ReadAll(dc)
			dc.Close()
			s.Mu.Lock()
			s.File = b
			s.Mu.Unlock()
			say("226 stored")
		case "SIZE":
			s.Mu.Lock()
			ok := s.Exists
			n := len(s.File)
			s.Mu.Unlock()
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
			s.Mu.Lock()
			s.Exists = true
			s.Mu.Unlock()
			say("250 renamed")
		case "DELE":
			s.Mu.Lock()
			ok := s.Exists
			s.Exists = false
			s.Mu.Unlock()
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
