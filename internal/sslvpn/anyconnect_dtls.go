package sslvpn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
)

// AnyConnect DTLS: the same CSTP packet types, one per DTLS 1.2 record
// (a type byte, then the packet), over UDP, which is faster than TCP for
// a tunnel. The DTLS key is not sent at all: with "PSK-NEGOTIATE" (what
// ocserv and current Cisco servers offer) both sides take it from the TLS
// connection (RFC 5705 exporter, label EXPORTER-openconnect-psk), and the
// session id in the ClientHello is the X-DTLS-App-ID the server gave, so
// it knows whose tunnel the UDP packets belong to.
//
// DTLS starts in the background once the TLS tunnel is up; packets use it
// as soon as it works and go back to TLS when it stops answering (UDP
// blocked on the way, a NAT that forgot it). Nothing is lost while it
// starts: the TLS tunnel carries everything until then.

const acPSKLabel = "EXPORTER-openconnect-psk"

// dtlsTimeout bounds the DTLS handshake; tests shorten it.
var dtlsTimeout = 10 * time.Second

type acDTLS struct {
	c    *dtls.Conn
	last atomic.Int64 // unix nanoseconds of the last record received
}

// dtlsHeaders are what the CONNECT request offers.
func dtlsHeaders() string {
	return "\r\nX-DTLS-CipherSuite: PSK-NEGOTIATE\r\nX-DTLS-Accept-Encoding: identity"
}

// dtlsOffer reads the server's DTLS answer: the UDP address and the app id,
// or ok false when it offers none komando can use.
func dtlsOffer(h http.Header, u *url.URL) (addr string, appID []byte, dpd time.Duration, ok bool) {
	if h.Get("X-DTLS-CipherSuite") != "PSK-NEGOTIATE" {
		return "", nil, 0, false
	}
	port, err := strconv.Atoi(h.Get("X-DTLS-Port"))
	if err != nil || port <= 0 || port > 65535 {
		return "", nil, 0, false
	}
	appID, err = hex.DecodeString(h.Get("X-DTLS-App-ID"))
	if err != nil || len(appID) == 0 || len(appID) > 32 {
		return "", nil, 0, false
	}
	dpd = 30 * time.Second
	if n, err := strconv.Atoi(h.Get("X-DTLS-DPD")); err == nil && n > 0 {
		dpd = time.Duration(n) * time.Second
	}
	return net.JoinHostPort(u.Hostname(), strconv.Itoa(port)), appID, dpd, true
}

// oneSession hands pion the "session" to offer: only its id matters (the
// server's app id); the server does not know it, so a full PSK handshake
// follows.
type oneSession struct{ s *dtls.Session }

func (o *oneSession) Set([]byte, dtls.Session) error { return nil }
func (o *oneSession) Del([]byte) error               { o.s = nil; return nil }
func (o *oneSession) Get([]byte) (dtls.Session, error) {
	if o.s == nil {
		return dtls.Session{}, nil
	}
	return *o.s, nil
}

var acPSKSuites = []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256, dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CBC_SHA256, dtls.TLS_PSK_WITH_AES_128_CCM}

// startDTLS opens the DTLS channel and, once it is up, moves packets to it.
func (t *acTun) startDTLS(c *tls.Conn, keys *tlsKeys, addr string, appID []byte, dpd, wait time.Duration) {
	psk, err := exportPSK(c, keys)
	if err != nil {
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return
	}
	secret := make([]byte, 48)
	rand.Read(secret)
	dc, err := dtls.ClientWithOptions(pc, raddr,
		dtls.WithPSK(func([]byte) ([]byte, error) { return psk, nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(acPSKSuites...),
		dtls.WithSessionStore(&oneSession{s: &dtls.Session{Version: 1, IsClient: true, ID: appID, Secret: secret,
			CipherSuiteID: acPSKSuites[0], PSKHash: sha256.Sum256(psk)}}),
		dtls.WithExtendedMasterSecret(dtls.RequestExtendedMasterSecret))
	if err != nil {
		pc.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	go func() {
		select {
		case <-t.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	err = dc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		dc.Close()
		pc.Close()
		return
	}
	d := &acDTLS{c: dc}
	d.last.Store(time.Now().UnixNano())
	t.udp.Store(d)
	stop := func() {
		if t.udp.CompareAndSwap(d, nil) {
			dc.Close()
			pc.Close()
		}
	}
	go func() { <-t.done; stop() }()
	go t.readDTLS(d, stop)
	go t.keepDTLS(d, dpd, stop)
}

// exportPSK is the DTLS key both sides take from the TLS connection.
// Go's own exporter refuses TLS 1.2 without Extended Master Secret, which
// is what ocserv negotiates by default; then komando computes the same
// RFC 5705 value from this connection's own keys.
func exportPSK(c *tls.Conn, keys *tlsKeys) ([]byte, error) {
	st := c.ConnectionState()
	if k, err := st.ExportKeyingMaterial(acPSKLabel, nil, 32); err == nil {
		return k, nil
	}
	return keys.export(st, acPSKLabel, 32)
}

func (d *acDTLS) send(typ byte, p []byte) error {
	b := make([]byte, 1+len(p))
	b[0] = typ
	copy(b[1:], p)
	_, err := d.c.Write(b)
	return err
}

func (t *acTun) readDTLS(d *acDTLS, stop func()) {
	defer stop()
	buf := make([]byte, 65536)
	for {
		n, err := d.c.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		d.last.Store(time.Now().UnixNano())
		switch buf[0] {
		case cstpData:
			t.deliver(append([]byte(nil), buf[1:n]...))
		case cstpDPDReq:
			d.send(cstpDPDResp, nil)
		case cstpDisconnect, cstpTerminate:
			t.end(errors.New("the VPN ended the session"))
			return
		case cstpCompressed:
			return // refused, as on TLS: stay on the TLS tunnel
		}
	}
}

// keepDTLS checks the channel every dpd: one that stopped answering is
// dropped, and packets go over TLS again.
func (t *acTun) keepDTLS(d *acDTLS, dpd time.Duration, stop func()) {
	tick := time.NewTicker(dpd)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
		}
		if t.udp.Load() != d {
			return
		}
		if time.Since(time.Unix(0, d.last.Load())) > 3*dpd {
			stop()
			return
		}
		d.send(cstpDPDReq, nil)
	}
}

// DTLS reports whether packets go over DTLS right now.
func (t *acTun) DTLS() bool { return t.udp.Load() != nil }
