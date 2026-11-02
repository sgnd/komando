package sshx

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// ExpandProxy fills in a ProxyCommand's tokens like OpenSSH: %h address,
// %p port, %r user, %n the name in the inventory, %% a percent sign.
func ExpandProxy(cmd string, h *store.Host) string {
	var sb strings.Builder
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != '%' || i+1 == len(cmd) {
			sb.WriteByte(cmd[i])
			continue
		}
		i++
		switch cmd[i] {
		case 'h':
			sb.WriteString(Q(h.Address))
		case 'p':
			sb.WriteString(strconv.Itoa(h.EffectivePort()))
		case 'r':
			sb.WriteString(Q(h.User))
		case 'n':
			sb.WriteString(Q(h.Name))
		case '%':
			sb.WriteByte('%')
		default:
			sb.WriteByte('%')
			sb.WriteByte(cmd[i])
		}
	}
	return sb.String()
}

// proxyConn is a connection carried by a local program's stdin and stdout.
type proxyConn struct {
	cmd    *exec.Cmd
	r, w   *os.File // our ends of the pipes
	stderr *bytes.Buffer
	addr   string // host:port of the server, for host-key checks
	once   sync.Once
}

// dialProxy starts h's ProxyCommand with sh, like OpenSSH does.
func dialProxy(h *store.Host) (*proxyConn, error) {
	line := ExpandProxy(h.ProxyCommand, h)
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	c := &proxyConn{cmd: exec.Command("/bin/sh", "-c", line), r: outR, w: inW, stderr: &bytes.Buffer{},
		addr: net.JoinHostPort(h.Address, strconv.Itoa(h.EffectivePort()))}
	c.cmd.Stdin, c.cmd.Stdout, c.cmd.Stderr = inR, outW, &limitedWriter{buf: c.stderr, max: 8 << 10}
	if err := c.cmd.Start(); err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, out.Errf(out.ExitConnect, "PROXY_FAILED", "check the program in --proxy-command is installed", "proxy command for %s: %v", h.Name, err)
	}
	inR.Close() // the child has its own copies
	outW.Close()
	return c, nil
}

func (c *proxyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *proxyConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *proxyConn) Close() error {
	c.once.Do(func() {
		c.w.Close()
		c.r.Close()
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
			_ = c.cmd.Wait()
		}
	})
	return nil
}

// stderrTail is what the proxy program said, for error messages.
func (c *proxyConn) stderrTail() string {
	s := strings.TrimSpace(c.stderr.String())
	if len(s) > 500 {
		s = s[len(s)-500:]
	}
	return s
}

type proxyAddr string

func (a proxyAddr) Network() string { return "proxy" }
func (a proxyAddr) String() string  { return string(a) }

// The remote address is the server's: known_hosts is checked against it.
func (c *proxyConn) LocalAddr() net.Addr  { return proxyAddr("127.0.0.1:0") }
func (c *proxyConn) RemoteAddr() net.Addr { return proxyAddr(c.addr) }

func (c *proxyConn) SetDeadline(t time.Time) error {
	if err := c.r.SetReadDeadline(t); err != nil {
		return nil // pipes without deadline support: the dial context still bounds the handshake
	}
	_ = c.w.SetWriteDeadline(t)
	return nil
}
func (c *proxyConn) SetReadDeadline(t time.Time) error  { _ = c.r.SetReadDeadline(t); return nil }
func (c *proxyConn) SetWriteDeadline(t time.Time) error { _ = c.w.SetWriteDeadline(t); return nil }

type limitedWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
