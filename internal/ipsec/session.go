package ipsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Options are what a client needs to connect.
type Options struct {
	Server   string // host or host:port of the IKE server
	PSK      string // pre-shared key (IKEv1; IKEv2 when no EAP)
	User     string // XAUTH / L2TP PPP / EAP user name
	Password string
	ID       string // IKEv1: the group name (aggressive mode); IKEv2: our identity
	RemoteID string // IKEv2: the server's identity (default: Server's host)
	CA       []byte // IKEv2: the CA that signed the server certificate (PEM); empty: the system's
	// Prompt asks a person for a one-time code (XAUTH); nil: nobody there.
	Prompt func(label string, secret bool) (string, error)
	Log    func(format string, args ...any)
	// Lifetime of the SAs komando proposes (0: 8h for IKE, 1h for ESP).
	Lifetime time.Duration
	// Debug logs every IKE message sent and received (sizes, types).
	Debug bool
	// LegacyCrypto lets IKEv1 also offer and accept 3DES and the small DH
	// groups 2 (1024-bit) and 5 (1536-bit), which old servers may still
	// need. They are weak, so a person turns this on for one VPN at a time.
	LegacyCrypto bool
}

func (o *Options) debugf(format string, args ...any) {
	if o.Debug {
		o.logf(format, args...)
	}
}

func (o *Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

// AuthError is a login the server refused.
type AuthError struct{ Msg string }

func (e *AuthError) Error() string { return e.Msg }

// LegacyCryptoError: the server accepted none of the strong IKEv1
// proposals and may speak only old, weak ciphers, which komando offers
// only when legacy crypto is allowed (Options.LegacyCrypto). The caller
// names the per-VPN setting that allows them.
type LegacyCryptoError struct{ Msg string }

func (e *LegacyCryptoError) Error() string { return e.Msg }

// legacyHint turns "accepted none of komando's proposals" into a
// LegacyCryptoError when legacy crypto is off.
func legacyHint(o *Options, err error) error {
	if err == nil || o.LegacyCrypto || !strings.Contains(err.Error(), "accepted none") {
		return err
	}
	return &LegacyCryptoError{Msg: err.Error() + "; if it only speaks old, weak ones (3DES, DH group 2 or 5), komando offers them only when legacy crypto is allowed for this VPN"}
}

// ErrNeedsPerson: the login asks for a one-time code and nobody is there.
var ErrNeedsPerson = errors.New("the VPN login asks for a one-time code; a person runs `komando vpn up NAME`")

// Session is an established IPsec connection: ESP SAs over UDP, kept up
// (dead peer detection, rekeys) until closed.
type Session struct {
	t *udpTransport

	mu      sync.Mutex
	out     *espSA
	in      map[uint32]*espSA
	retired map[uint32]time.Time // inbound SAs kept a little after a rekey

	deliver       func(next byte, payload []byte)
	log           func(format string, args ...any)
	unknownLogged time.Time
	done          chan struct{}
	err           error
	once          sync.Once
	closers       []func()

	// tunnel mode: the address and DNS servers the server gave
	Address netip.Addr
	DNS     []netip.Addr
}

func newSession(t *udpTransport) *Session {
	s := &Session{t: t, in: map[uint32]*espSA{}, retired: map[uint32]time.Time{}, done: make(chan struct{})}
	t.esp = s.inbound
	go func() {
		select {
		case <-t.done:
			s.end(fmt.Errorf("the connection to the server ended: %v", t.err))
		case <-s.done:
		}
	}()
	return s
}

// install makes sa the outbound SA and adds its inbound half. The old
// inbound SA stays until the server deletes it or its time is surely over:
// some servers (IKEv1) keep sending on the old SA long after a rekey.
func (s *Session) install(sa *espSA) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.out != nil {
		s.retired[s.out.spiIn] = time.Now().Add(retireAfter)
	}
	s.out = sa
	s.in[sa.spiIn] = sa
	for spi, t := range s.retired {
		if time.Now().After(t) {
			delete(s.in, spi)
			delete(s.retired, spi)
		}
	}
}

// remove forgets an SA the server deleted; it reports whether that was
// the current one.
func (s *Session) remove(spiOut uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for spi, sa := range s.in {
		if sa.spiOut == spiOut {
			delete(s.in, spi)
			delete(s.retired, spi)
		}
	}
	return s.out != nil && s.out.spiOut == spiOut
}

// inFor finds our inbound SPI of the SA whose outbound SPI is spiOut.
func (s *Session) inFor(spiOut uint32) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for spi, sa := range s.in {
		if sa.spiOut == spiOut {
			return spi, true
		}
	}
	return 0, false
}

var netip0 netip.Addr

// retireAfter is how long an inbound SA stays after a rekey, unless the
// server deletes it first: longer than any ESP lifetime komando accepts.
var retireAfter = 2 * time.Hour

func (s *Session) currentOut() *espSA {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out
}

func (s *Session) inbound(pkt []byte) {
	spi := binary.BigEndian.Uint32(pkt)
	s.mu.Lock()
	sa := s.in[spi]
	d := s.deliver
	warn := sa == nil && time.Since(s.unknownLogged) > time.Minute
	if warn {
		s.unknownLogged = time.Now()
	}
	s.mu.Unlock()
	if warn && s.log != nil {
		s.log("ESP: dropped packets for SPI %08x, which komando does not know (an SA the server still uses?)", spi)
	}
	if sa == nil || d == nil {
		return
	}
	next, payload, err := sa.open(pkt)
	if err != nil {
		return
	}
	d(next, payload)
}

// send seals one payload on the current SA.
func (s *Session) send(next byte, payload []byte) error {
	sa := s.currentOut()
	if sa == nil {
		return errors.New("no IPsec SA")
	}
	pkt, err := sa.seal(next, payload)
	if err != nil {
		return err
	}
	return s.t.sendESP(pkt)
}

// Done is closed when the session ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err says why the session ended.
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

func (s *Session) end(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
		for i := len(s.closers) - 1; i >= 0; i-- {
			s.closers[i]()
		}
		s.t.end(err)
	})
}

// Close ends the session, telling the server.
func (s *Session) Close() error {
	s.end(errors.New("closed"))
	return nil
}

// What runs over the session.

// L2TPLink carries L2TP over ESP transport mode: UDP port 1701 both ways.
type L2TPLink struct {
	s    *Session
	recv chan []byte
}

// L2TP returns the session's L2TP datagram link.
func (s *Session) L2TP() *L2TPLink {
	l := &L2TPLink{s: s, recv: make(chan []byte, 256)}
	s.mu.Lock()
	s.deliver = func(next byte, p []byte) {
		if next != nextUDP || len(p) < 8 || binary.BigEndian.Uint16(p[2:]) != 1701 {
			return
		}
		n := int(binary.BigEndian.Uint16(p[4:]))
		if n < 8 || n > len(p) {
			n = len(p)
		}
		select {
		case l.recv <- p[8:n]:
		default:
		}
	}
	s.mu.Unlock()
	return l
}

// Send sends one L2TP datagram. The UDP checksum is 0 (allowed for IPv4;
// ESP already protects the datagram).
func (l *L2TPLink) Send(b []byte) error {
	h := []byte{0x06, 0xa5, 0x06, 0xa5, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(b)))
	return l.s.send(nextUDP, append(h, b...))
}

func (l *L2TPLink) Recv() <-chan []byte   { return l.recv }
func (l *L2TPLink) Done() <-chan struct{} { return l.s.done }

// Tunnel is a tunnel-mode session: IPv4 packets in and out.
type Tunnel struct {
	*Session
	packets chan []byte
}

// Tunnel returns the session as a packet tunnel.
func (s *Session) Tunnel() *Tunnel {
	t := &Tunnel{Session: s, packets: make(chan []byte, 256)}
	s.mu.Lock()
	s.deliver = func(next byte, p []byte) {
		if next != nextIPv4 {
			return
		}
		select {
		case t.packets <- p:
		default:
		}
	}
	s.mu.Unlock()
	return t
}

func (t *Tunnel) WritePacket(p []byte) error { return t.send(nextIPv4, p) }
func (t *Tunnel) Packets() <-chan []byte     { return t.packets }
func (t *Tunnel) Addresses() []netip.Addr    { return []netip.Addr{t.Address} }
func (t *Tunnel) DNS() []netip.Addr          { return t.Session.DNS }
func (t *Tunnel) MTU() int                   { return 1400 }
