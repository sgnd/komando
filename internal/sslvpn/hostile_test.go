package sslvpn

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// discard is a connection that takes every write.
type discard struct{ net.Conn }

func (discard) Write(b []byte) (int, error) { return len(b), nil }

// What a VPN server sends must never panic komando.
func TestHostileServerNoPanic(t *testing.T) {
	// Pulse ESP keys cut short: espReply copied past the end
	short := make([]byte, 0x5a)
	short[0x29] = 0x40 // the key length it checks
	if err := espReply(&iftConn{c: discard{}}, short); err == nil {
		t.Error("short ESP keys were answered")
	}
	ok := make([]byte, 0x6a)
	ok[0x29] = 0x40
	if err := espReply(&iftConn{c: discard{}}, ok); err != nil {
		t.Errorf("ESP keys of the full size: %v", err)
	}
	// a DPD interval that overflows a Duration: NewTicker panicked
	huge := strconv.Itoa(math.MaxInt64)
	h := http.Header{"X-Dtls-Ciphersuite": {"PSK-NEGOTIATE"}, "X-Dtls-Port": {"443"}, "X-Dtls-App-Id": {"0102"}, "X-Dtls-Dpd": {huge}}
	if _, _, dpd, okay := dtlsOffer(h, &url.URL{Host: "vpn.example"}); !okay || dpd <= 0 || dpd > time.Hour {
		t.Errorf("DTLS DPD %v (%v)", dpd, okay)
	}
	for _, v := range []string{huge, "-5", "0", "x"} {
		if d, ok := seconds(v, 3600); ok && (d <= 0 || d > time.Hour) {
			t.Errorf("seconds(%q) = %v", v, d)
		}
	}
	if d := gpRekey(huge); d <= 0 || d > 7*24*time.Hour {
		t.Errorf("GlobalProtect rekey for a huge timeout: %v", d)
	}
	// an IPv6 address in PPP's IPCP request: As4 panicked
	p := newPPP(func(uint16, []byte) error { return nil })
	p.addr = netip.MustParseAddr("2001:db8::1")
	p.dns = []netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("192.0.2.53")}
	if err := p.ipcpRequest(); err != nil {
		t.Fatal(err)
	}
	if a, ok := ipv4(netip.MustParseAddr("::ffff:192.0.2.1")); !ok || a.String() != "192.0.2.1" {
		t.Errorf("an IPv4-mapped address: %v", a)
	}
}

// The PPP control packets come from the server.
func FuzzPPP(f *testing.F) {
	f.Add(uint16(pppIPCP), []byte{3, 1, 0, 10, 3, 6, 10, 0, 0, 1})
	f.Add(uint16(pppLCP), []byte{1, 1, 0, 8, 5, 6, 1, 2})
	f.Fuzz(func(t *testing.T, proto uint16, b []byte) {
		p := newPPP(func(uint16, []byte) error { return nil })
		for _, pr := range []uint16{proto, pppLCP, pppIPCP, pppIPV6CP} {
			p.handle(pr, b)
		}
		p.ipcpRequest()
	})
}

// Pulse's ESP key messages come from the server.
func FuzzPulseESP(f *testing.F) {
	f.Add(make([]byte, 0x6a))
	f.Fuzz(func(t *testing.T, b []byte) {
		espReply(&iftConn{c: discard{}}, b)
	})
}
