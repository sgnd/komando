package sshx

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// ExpandProxy fills in a ProxyCommand's tokens like OpenSSH: %h address,
// %p port, %r user, %n the name in the inventory, %% a percent sign. Each
// value is quoted for sh.
func ExpandProxy(cmd string, h *store.Host) string {
	s, _ := expandProxy(cmd, h, func(v string) (string, error) { return Q(v), nil })
	return s
}

// expandProxy is ExpandProxy with the quoting of the shell that runs the
// line; quote refuses a value that shell cannot hold safely.
func expandProxy(cmd string, h *store.Host, quote func(string) (string, error)) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != '%' || i+1 == len(cmd) {
			sb.WriteByte(cmd[i])
			continue
		}
		i++
		var v string
		switch cmd[i] {
		case 'h':
			v = h.Address
		case 'r':
			v = h.User
		case 'n':
			v = h.Name
		case 'p':
			sb.WriteString(strconv.Itoa(h.EffectivePort()))
			continue
		case '%':
			sb.WriteByte('%')
			continue
		default:
			sb.WriteByte('%')
			sb.WriteByte(cmd[i])
			continue
		}
		q, err := quote(v)
		if err != nil {
			return "", err
		}
		sb.WriteString(q)
	}
	return sb.String(), nil
}

var cmdBare = regexp.MustCompile(`^[A-Za-z0-9._@:\[\]-]+$`)

// quoteCmd puts v in a cmd.exe command line as one word. Inside double
// quotes cmd.exe reads & | < > ^ as text, but it still expands %NAME%
// (and !NAME! when delayed expansion is on, which proxyCommand turns off),
// and a " would end the quotes: a value with % " or a line break is
// refused, so it can never run a command of its own.
func quoteCmd(v string) (string, error) {
	if cmdBare.MatchString(v) {
		return v, nil
	}
	if strings.ContainsAny(v, "\"%\r\n\x00") {
		return "", fmt.Errorf("%q cannot go into a Windows proxy command safely", v)
	}
	return `"` + v + `"`, nil
}

// proxyConn is a connection carried by a local program's stdin and stdout.
type proxyConn struct {
	cmd    *exec.Cmd
	r, w   *os.File // our ends of the pipes
	stderr *bytes.Buffer
	addr   string // host:port of the server, for host-key checks
	once   sync.Once
}

// dialProxy starts h's ProxyCommand with sh, like OpenSSH does (with
// cmd.exe on Windows).
func dialProxy(h *store.Host) (*proxyConn, error) {
	line, err := expandProxy(h.ProxyCommand, h, proxyQuote)
	if err != nil {
		return nil, proxyValueRefused(h, err)
	}
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
	c := &proxyConn{cmd: proxyCommand(line), r: outR, w: inW, stderr: &bytes.Buffer{},
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

// proxyValueRefused is the error for a server whose address, user or name
// the proxy command's shell cannot hold safely (cmd.exe on Windows).
func proxyValueRefused(h *store.Host, err error) error {
	return out.Errf(out.ExitConnect, "PROXY_FAILED", "check the server's address, user and name", "proxy command for %s: %v", h.Name, err)
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
