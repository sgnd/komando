// Package proxytest is a small HTTP CONNECT proxy for tests. Every tunnel
// goes to one backend address, whatever host the client asks for, so a
// test can use a name like example.com and still reach its own server.
package proxytest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
)

// Proxy records what it was asked.
type Proxy struct {
	URL string // http://127.0.0.1:PORT

	mu    sync.Mutex
	hosts []string
	auth  []string
}

// Hosts are the CONNECT targets asked for so far.
func (p *Proxy) Hosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...)
}

// Auth are the Proxy-Authorization headers sent so far.
func (p *Proxy) Auth() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auth...)
}

// Start runs a proxy that tunnels every CONNECT to backend until the test
// ends. A status other than 200 refuses every tunnel with it.
func Start(t testing.TB, backend string, status int) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &Proxy{URL: "http://" + ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c, backend, status)
		}
	}()
	return p
}

func (p *Proxy) serve(c net.Conn, backend string, status int) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.hosts = append(p.hosts, req.Host)
	p.auth = append(p.auth, req.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	if req.Method != http.MethodConnect || status != http.StatusOK {
		if status == http.StatusOK {
			status = http.StatusMethodNotAllowed
		}
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
		return
	}
	b, err := net.Dial("tcp", backend)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer b.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go io.Copy(b, br)
	io.Copy(c, b)
}
