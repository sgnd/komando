package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// udpTransport carries IKE on UDP 500 until NAT traversal starts, then IKE
// (behind four zero bytes) and ESP on UDP 4500 (RFC 3948).
type udpTransport struct {
	server netip.Addr
	port   int // the server's IKE port (500 unless a test says otherwise)

	mu     sync.Mutex
	conn   *net.UDPConn
	natt   bool
	closed bool

	routes map[[8]byte]chan []byte // IKE messages by the initiator's SPI (ours)
	esp    func([]byte)
	done   chan struct{}
	err    error
	once   sync.Once
}

// resolve finds the server's IPv4 address (komando's tunnels are IPv4
// inside, and IPv4 outside is what VPN servers answer on almost always).
func resolve(ctx context.Context, host string) (netip.Addr, int, error) {
	port := 500
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
			return netip.Addr{}, 0, fmt.Errorf("bad port in %q", host)
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), port, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, 0, fmt.Errorf("cannot find the VPN server %s: %v", host, err)
	}
	return ips[0].Unmap(), port, nil
}

func newTransport(ctx context.Context, server string) (*udpTransport, error) {
	addr, port, err := resolve(ctx, server)
	if err != nil {
		return nil, err
	}
	t := &udpTransport{server: addr, port: port, routes: map[[8]byte]chan []byte{}, done: make(chan struct{})}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, uint16(port))))
	if err != nil {
		return nil, err
	}
	t.conn = c
	go t.read(c, false)
	return t, nil
}

func (t *udpTransport) read(c *net.UDPConn, natt bool) {
	buf := make([]byte, 65536)
	for {
		n, err := c.Read(buf)
		if err != nil {
			t.mu.Lock()
			current := t.conn == c
			t.mu.Unlock()
			if current && errors.Is(err, syscall.ECONNREFUSED) {
				continue // an ICMP error for an earlier packet; keep listening
			}
			if current {
				t.end(err)
			}
			return
		}
		b := buf[:n]
		switch {
		case !natt:
			t.deliverIKE(b)
		case n == 1 && b[0] == 0xff: // NAT keepalive
		case n >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0:
			t.deliverIKE(b[4:])
		case n >= 8:
			if t.esp != nil {
				t.esp(append([]byte{}, b...))
			}
		}
	}
}

func (t *udpTransport) deliverIKE(b []byte) {
	if len(b) < 28 {
		return
	}
	t.mu.Lock()
	ch := t.routes[[8]byte(b[:8])]
	t.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- append([]byte{}, b...):
	default: // nobody reads fast enough: IKE retransmits
	}
}

// route sends the IKE messages of the SA whose initiator SPI is spi to a
// new channel.
func (t *udpTransport) route(spi []byte) chan []byte {
	ch := make(chan []byte, 32)
	t.mu.Lock()
	t.routes[[8]byte(spi)] = ch
	t.mu.Unlock()
	return ch
}

func (t *udpTransport) unroute(spi []byte) {
	t.mu.Lock()
	delete(t.routes, [8]byte(spi))
	t.mu.Unlock()
}

// startNATT moves to UDP 4500.
func (t *udpTransport) startNATT() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.natt {
		return nil
	}
	port := 4500
	if t.port != 500 {
		port = t.port + 1 // tests run the server on other ports
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(t.server, uint16(port))))
	if err != nil {
		return err
	}
	old := t.conn
	t.conn, t.natt = c, true
	old.Close()
	go t.read(c, true)
	go t.keepalive(c)
	return nil
}

func (t *udpTransport) keepalive(c *net.UDPConn) {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			c.Write([]byte{0xff})
		}
	}
}

func (t *udpTransport) sendIKE(b []byte) error {
	t.mu.Lock()
	c, natt := t.conn, t.natt
	t.mu.Unlock()
	if natt {
		b = append([]byte{0, 0, 0, 0}, b...)
	}
	_, err := c.Write(b)
	return err
}

func (t *udpTransport) sendESP(b []byte) error {
	t.mu.Lock()
	c, natt := t.conn, t.natt
	t.mu.Unlock()
	if !natt {
		return errors.New("ESP before NAT traversal")
	}
	_, err := c.Write(b)
	return err
}

// local is this computer's address and port toward the server.
func (t *udpTransport) local() netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (t *udpTransport) end(err error) {
	t.once.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.err = err
		c := t.conn
		t.mu.Unlock()
		close(t.done)
		c.Close()
	})
}
