package storex

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

// dirFTP is a plain-FTP server over a local folder: enough of LIST, RETR,
// STOR, SIZE, MKD, RNFR/RNTO and DELE for every Bucket call. Like many
// servers, RNTO never renames over an existing file.
type dirFTP struct {
	ln   net.Listener
	root string
}

func newDirFTP(t *testing.T) *dirFTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dirFTP{ln: ln, root: t.TempDir()}
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

func (s *dirFTP) p(name string) string {
	return filepath.Join(s.root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
}

func (s *dirFTP) open(t *testing.T) Bucket {
	t.Helper()
	b, err := OpenFTP(context.Background(), driver.Target{Address: s.ln.Addr().String(), User: "u", Prefix: "site/"}, "p", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func (s *dirFTP) serve(c net.Conn) {
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
		cmd, arg, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch strings.ToUpper(cmd) {
		case "USER":
			say("331 password")
		case "PASS":
			say("230 in")
		case "FEAT":
			say("211 no features")
		case "TYPE", "OPTS":
			say("200 ok")
		case "EPSV":
			if data != nil {
				data.Close()
			}
			data, _ = net.Listen("tcp", "127.0.0.1:0")
			say("229 ok (|||%d|)", data.Addr().(*net.TCPAddr).Port)
		case "LIST":
			es, err := os.ReadDir(s.p(arg))
			if err != nil {
				say("550 no such folder")
				continue
			}
			dc, err := data.Accept()
			if err != nil {
				return
			}
			say("150 here")
			for _, e := range es {
				fi, _ := e.Info()
				kind := "-rw-r--r--"
				if e.IsDir() {
					kind = "drwxr-xr-x"
				}
				fmt.Fprintf(dc, "%s 1 u u %d Nov 07 12:00 %s\r\n", kind, fi.Size(), e.Name())
			}
			dc.Close()
			say("226 done")
		case "RETR":
			b, err := os.ReadFile(s.p(arg))
			if err != nil {
				say("550 no such file")
				continue
			}
			dc, err := data.Accept()
			if err != nil {
				return
			}
			say("150 here")
			dc.Write(b)
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
			if os.WriteFile(s.p(arg), b, 0o644) != nil {
				say("553 cannot store")
				continue
			}
			say("226 stored")
		case "SIZE":
			fi, err := os.Stat(s.p(arg))
			if err != nil || fi.IsDir() {
				say("550 no such file")
				continue
			}
			say("213 %d", fi.Size())
		case "MKD":
			if os.Mkdir(s.p(arg), 0o755) != nil {
				say("550 cannot make it")
				continue
			}
			say("257 made")
		case "RNFR":
			if _, err := os.Stat(s.p(arg)); err != nil {
				say("550 no such file")
				continue
			}
			rnfr = arg
			say("350 ready")
		case "RNTO":
			if _, err := os.Stat(s.p(arg)); err == nil {
				say("553 it exists")
				continue
			}
			if os.Rename(s.p(rnfr), s.p(arg)) != nil {
				say("553 cannot rename")
				continue
			}
			say("250 renamed")
		case "DELE":
			if os.Remove(s.p(arg)) != nil {
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
