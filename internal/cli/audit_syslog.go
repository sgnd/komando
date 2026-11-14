package cli

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// The audit log can also go to a log server (a SIEM), as each record is
// written: syslog (RFC 5424) over UDP, TCP or TLS (RFC 5425, octet
// counting). The local file stays the record; a log server that does not
// answer is said once on stderr, and the command goes on.

// syslogTarget checks an audit_syslog value: udp://HOST[:514],
// tcp://HOST[:514] or tls://HOST[:6514]; "" or off turns it off.
func syslogTarget(v string) (network, addr string, err error) {
	if v == "" || v == "off" {
		return "", "", nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.User != nil || u.RawQuery != "" {
		return "", "", out.Errf(out.ExitUsage, "USAGE", "use udp://HOST:514, tcp://HOST:514 or tls://HOST:6514 (or off)", "audit_syslog %q is not a syslog address", v)
	}
	port := u.Port()
	switch u.Scheme {
	case "udp", "tcp":
		if port == "" {
			port = "514"
		}
	case "tls":
		if port == "" {
			port = "6514"
		}
	default:
		return "", "", out.Errf(out.ExitUsage, "USAGE", "use udp://, tcp:// or tls://", "audit_syslog: %q is not udp, tcp or tls", u.Scheme)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", out.Errf(out.ExitUsage, "USAGE", "a port is 1 to 65535", "audit_syslog: the port %q is not a number from 1 to 65535", port)
	}
	return u.Scheme, net.JoinHostPort(u.Hostname(), port), nil
}

var syslogWarned sync.Once

// sendSyslog sends one audit record (its JSON line) to the log server.
func sendSyslog(cl *call, target string, line []byte, ts time.Time) {
	network, addr, err := syslogTarget(target)
	if err != nil || network == "" {
		return
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "-"
	}
	// PRI 86 = facility authpriv (10) * 8 + severity info (6)
	msg := fmt.Sprintf("<86>1 %s %s komando %d audit - %s", ts.UTC().Format(time.RFC3339Nano), sdName(host), os.Getpid(), line)
	if err := deliver(network, addr, msg); err != nil {
		syslogWarned.Do(func() {
			fmt.Fprintf(cl.out.Err, "Warning: the audit record was not sent to %s (%v); it is in the local audit log\n", target, err)
		})
	}
}

func deliver(network, addr, msg string) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	var c net.Conn
	var err error
	switch network {
	case "udp":
		c, err = d.Dial("udp", addr)
	case "tcp":
		c, err = d.Dial("tcp", addr)
	case "tls":
		host, _, _ := net.SplitHostPort(addr)
		c, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	}
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	frame := msg
	if network != "udp" {
		frame = strconv.Itoa(len(msg)) + " " + msg // octet counting (RFC 6587, 5425)
	}
	_, err = c.Write([]byte(frame))
	return err
}

// sdName keeps a header field printable ASCII without spaces.
func sdName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return '-'
		}
		return r
	}, s)
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}
