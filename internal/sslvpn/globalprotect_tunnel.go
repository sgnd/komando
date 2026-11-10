package sslvpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The GlobalProtect tunnel (GPST inside TLS); the login is in
// globalprotect.go.

type gpTun struct {
	base
	o  Options
	s  GPSession
	u  *url.URL
	hc *http.Client

	wmu sync.Mutex // guards c and writes on it
	c   *tls.Conn
}

// How long the tunnel waits for a frame: the gateway answers every
// keepalive, so a silent link is a dead one.
var (
	gpKeepalive   = 10 * time.Second
	gpReadTimeout = 60 * time.Second
	// how long a dropped tunnel is redialed before the session ends
	gpRedialFor = 5 * time.Minute
)

type gpConfig struct {
	IP  string   `xml:"ip-address"`
	MTU string   `xml:"mtu"`
	DNS []string `xml:"dns>member"`
	// Timeout is how long the gateway keeps one tunnel (seconds); the
	// client sets the tunnel up again before then, with the same login
	Timeout string `xml:"timeout"`
	// HSKey marks a gateway behind a load balancer (see below).
	HSKey string `xml:"hs-key>val"`
}

// GlobalProtectTunnel reads the config and opens the tunnel.
func GlobalProtectTunnel(ctx context.Context, o Options, s GPSession) (Tunnel, error) {
	u, err := portalURL(firstNonEmptyS(s.Gateway, o.Portal))
	if err != nil {
		return nil, err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return nil, err
	}
	t := &gpTun{base: newBase(), o: o, s: s, u: u, hc: hc}
	cfg, err := t.getconfig(ctx)
	if err != nil {
		return nil, err
	}
	a, _ := netip.ParseAddr(cfg.IP)
	t.addrs = []netip.Addr{a}
	for _, d := range cfg.DNS {
		if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			t.dns = append(t.dns, a)
		}
	}
	if n, err := strconv.Atoi(cfg.MTU); err == nil && n > 576 {
		t.mtu = n
	}
	c, err := t.connect(ctx)
	if err != nil {
		return nil, err
	}
	t.c = c
	t.closeFn = func() {
		t.wmu.Lock()
		t.c.Close()
		t.wmu.Unlock()
	}
	go t.read(c)
	go t.keepalive(gpRekey(cfg.Timeout))
	return t, nil
}

// gpRekey is when to set the tunnel up again: a minute before the
// gateway's own timeout ends it, as the GlobalProtect app does.
func gpRekey(timeout string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(timeout))
	if err != nil || n <= 120 {
		return 0
	}
	return time.Duration(n-60) * time.Second
}

func (t *gpTun) getconfig(ctx context.Context) (gpConfig, error) {
	var cfg gpConfig
	s, u := t.s, t.u
	cfgForm := url.Values{"client-type": {"1"}, "protocol-version": {"p1"}, "internal": {"no"}, "app-version": {firstNonEmptyS(s.AppVersion, gpAppVersion)},
		"os-version": {gpOS()}, "clientos": {gpOS()}, "hmac-algo": {"sha1,md5,sha256"}, "enc-algo": {"aes-128-cbc,aes-256-cbc"},
		"preferred-ip": {""}, "user": {s.User}, "authcookie": {s.AuthCookie}, "portal": {s.Portal}, "domain": {s.Domain}, "computer": {s.Computer}}
	if len(t.addrs) > 0 { // a re-setup asks for the address it has
		cfgForm.Set("preferred-ip", t.addrs[0].String())
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u.Scheme+"://"+u.Host+"/ssl-vpn/getconfig.esp", strings.NewReader(cfgForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", gpUserAgent)
	resp, err := t.hc.Do(req)
	if err != nil {
		return cfg, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cfg, &LoginError{Msg: "the gateway refused the session; log in again (" + resp.Status + gpWhy(b) + ")"}
	}
	if err := xml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("the gateway's config: %w", err)
	}
	if cfg.HSKey != "" {
		// Prisma Access gateways behind a load balancer ("NLB") hand out a
		// stand-in address (127.127.127.127) and a handshake key: the real
		// address comes from a handshake komando does not speak yet
		why := "gateway " + u.Hostname() + " connects in a way komando does not speak yet (a Prisma Access gateway behind a load balancer)"
		if s.Others != "" {
			why += "; add one of the portal's other gateways as this VPN's --portal instead: " + strings.ReplaceAll(s.Others, ",", ", ")
		}
		return cfg, &LoginError{Msg: why}
	}
	if _, err := netip.ParseAddr(cfg.IP); err != nil {
		return cfg, errors.New("the gateway gave no address" + gpConfigWhy(b))
	}
	return cfg, nil
}

// connect opens one GPST tunnel with the session's login.
func (t *gpTun) connect(ctx context.Context) (*tls.Conn, error) {
	c, err := dialTLS(ctx, t.o, t.u)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write([]byte("GET /ssl-tunnel-connect.sslvpn?" + url.Values{"user": {t.s.User}, "authcookie": {t.s.AuthCookie}}.Encode() + " HTTP/1.1\r\nHost: " + t.u.Host + "\r\n\r\n")); err != nil {
		c.Close()
		return nil, err
	}
	start := make([]byte, 12)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(c, start); err != nil {
		c.Close()
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	c.SetReadDeadline(time.Time{})
	if string(start) != "START_TUNNEL" {
		c.Close()
		return nil, &LoginError{Msg: "the gateway refused the tunnel: " + strings.TrimSpace(string(start))}
	}
	return c, nil
}

// redial sets the tunnel up again after it dropped or timed out. The
// login lasts hours, a tunnel much less, so a drop is not the end: only
// a gateway that refuses the login, a new address, or no tunnel for
// gpRedialFor ends the session.
func (t *gpTun) redial(why error) {
	deadline := time.Now().Add(gpRedialFor)
	wait := time.Second
	for {
		select {
		case <-t.done:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		go func() {
			select {
			case <-t.done:
				cancel()
			case <-ctx.Done():
			}
		}()
		cfg, err := t.getconfig(ctx)
		if err == nil && cfg.IP != t.addrs[0].String() {
			cancel()
			t.end(fmt.Errorf("connection to the VPN lost: the gateway gave a new address (%s, was %s); reconnect", cfg.IP, t.addrs[0]))
			return
		}
		var c *tls.Conn
		if err == nil {
			c, err = t.connect(ctx)
		}
		cancel()
		if err == nil {
			t.wmu.Lock()
			select {
			case <-t.done: // closed while redialing
				t.wmu.Unlock()
				c.Close()
				return
			default:
			}
			t.c = c
			t.wmu.Unlock()
			go t.read(c)
			return
		}
		var le *LoginError
		if errors.As(err, &le) || time.Now().After(deadline) {
			t.end(fmt.Errorf("connection to the VPN lost (%v); setting it up again failed: %w", why, err))
			return
		}
		select {
		case <-t.done:
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

func (t *gpTun) write(b []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.c.SetWriteDeadline(time.Now().Add(gpReadTimeout))
	_, err := t.c.Write(b)
	return err
}

func (t *gpTun) frame(p []byte) error {
	b := make([]byte, 16, 16+len(p))
	binary.BigEndian.PutUint32(b, 0x1a2b3c4d)
	binary.BigEndian.PutUint16(b[4:], 0x0800)
	binary.BigEndian.PutUint16(b[6:], uint16(len(p)))
	b[8] = 1
	b = append(b, p...)
	return t.write(b)
}

// gpKeepaliveFrame is the GPST keepalive: the magic and twelve zero
// bytes. An empty IPv4 frame is not one, and the gateway drops a tunnel
// it hears no keepalive on.
var gpKeepaliveFrame = []byte{0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func (t *gpTun) WritePacket(p []byte) error {
	// a failed write while the tunnel is being set up again is a lost
	// packet, not a lost session: TCP inside sends it again
	if err := t.frame(p); err != nil {
		select {
		case <-t.done:
			return err
		default:
			return nil
		}
	}
	return nil
}

func (t *gpTun) Close() error { t.end(net.ErrClosed); return nil }

// read reads frames from one connection; when it fails the tunnel is
// set up again.
func (t *gpTun) read(c *tls.Conn) {
	hdr := make([]byte, 16)
	for {
		c.SetReadDeadline(time.Now().Add(gpReadTimeout))
		if _, err := io.ReadFull(c, hdr); err != nil {
			c.Close()
			t.redial(err)
			return
		}
		if binary.BigEndian.Uint32(hdr) != 0x1a2b3c4d {
			t.end(errors.New("the VPN sent a broken frame"))
			return
		}
		n := binary.BigEndian.Uint16(hdr[6:])
		if n == 0 {
			continue // keepalive
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(c, p); err != nil {
			c.Close()
			t.redial(err)
			return
		}
		if binary.BigEndian.Uint16(hdr[4:]) == 0x0800 {
			t.deliver(p)
		}
	}
}

// keepalive sends keepalives, and sets the tunnel up again before the
// gateway's timeout (rekey; 0 when it named none).
func (t *gpTun) keepalive(rekey time.Duration) {
	tick := time.NewTicker(gpKeepalive)
	defer tick.Stop()
	var again <-chan time.Time
	if rekey > 0 {
		r := time.NewTicker(rekey)
		defer r.Stop()
		again = r.C
	}
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			t.write(gpKeepaliveFrame) // a failed write: read fails too and redials
		case <-again:
			// closing the connection makes read set up a new one
			t.wmu.Lock()
			t.c.Close()
			t.wmu.Unlock()
		}
	}
}
