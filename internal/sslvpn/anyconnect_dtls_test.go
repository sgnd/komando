package sslvpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

// fakeOcserv serves the CSTP tunnel over TLS (echoing packets with a 0xee
// mark) and offers DTLS on udpPort. dtlsUp, when set, is the DTLS side:
// it takes the PSK from the TLS connection the same way and echoes with
// a 0xdd mark.
func fakeOcserv(t *testing.T, udpPort int, dtlsUp func(psk []byte)) Options {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("X-DTLS-CipherSuite") != "PSK-NEGOTIATE" {
			t.Errorf("CONNECT offers DTLS %q", r.Header.Get("X-DTLS-CipherSuite"))
		}
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		st := c.(*tls.Conn).ConnectionState()
		psk, err := st.ExportKeyingMaterial(acPSKLabel, nil, 32)
		if err != nil {
			t.Error(err)
			return
		}
		if dtlsUp != nil {
			dtlsUp(psk)
		}
		fmt.Fprintf(c, "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 192.168.99.5\r\nX-CSTP-MTU: 1400\r\nX-DTLS-MTU: 1350\r\n"+
			"X-DTLS-CipherSuite: PSK-NEGOTIATE\r\nX-DTLS-App-ID: %s\r\nX-DTLS-Port: %d\r\nX-DTLS-DPD: 1\r\n\r\n", hex.EncodeToString([]byte("app-id-0123456789")), udpPort)
		br := brw.Reader
		hdr := make([]byte, 8)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			p := make([]byte, binary.BigEndian.Uint16(hdr[4:]))
			io.ReadFull(br, p)
			out := []byte("STF\x01\x00\x00\x00\x00")
			switch hdr[6] {
			case cstpData:
				p = append(p, 0xee)
			case cstpDPDReq:
				out[6], p = cstpDPDResp, nil
			default:
				continue
			}
			binary.BigEndian.PutUint16(out[4:], uint16(len(p)))
			c.Write(append(out, p...))
		}
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return Options{Portal: "https://" + srv.Listener.Addr().String(), CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
}

func echoMark(t *testing.T, tun Tunnel) byte {
	t.Helper()
	if err := tun.WritePacket([]byte{0x45, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-tun.Packets():
		if len(p) != 5 || string(p[:4]) != string([]byte{0x45, 1, 2, 3}) {
			t.Fatalf("echoed %x", p)
		}
		return p[4]
	case <-time.After(3 * time.Second):
		t.Fatal("no packet back")
	}
	return 0
}

func TestAnyConnectDTLS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // a free port for the DTLS side
	if err != nil {
		t.Fatal(err)
	}
	pskc := make(chan []byte, 1)
	// the PSK is known only after the TLS tunnel, so the DTLS side
	// listens on that port only then
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	o := fakeOcserv(t, port, func(psk []byte) { pskc <- psk })
	o.User = "e2e"
	go func() {
		psk := <-pskc
		l, err := dtls.ListenWithOptions("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			dtls.WithPSK(func([]byte) ([]byte, error) { return psk, nil }), dtls.WithCipherSuites(acPSKSuites...))
		if err != nil {
			t.Error(err)
			return
		}
		defer l.Close()
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			switch buf[0] {
			case cstpData:
				c.Write(append(append([]byte{cstpData}, buf[1:n]...), 0xdd))
			case cstpDPDReq:
				c.Write([]byte{cstpDPDResp})
			}
		}
	}()
	tun, err := AnyConnectTunnel(context.Background(), o, "COOKIE")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.MTU() != 1350 {
		t.Errorf("MTU %d: packets must fit DTLS too", tun.MTU())
	}
	for i := 0; i < 50 && !tun.(*acTun).DTLS(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !tun.(*acTun).DTLS() {
		t.Fatal("DTLS did not come up")
	}
	if m := echoMark(t, tun); m != 0xdd {
		t.Errorf("packet went over %x, want DTLS", m)
	}
	time.Sleep(2500 * time.Millisecond) // a few DPD rounds: DTLS stays
	if m := echoMark(t, tun); m != 0xdd {
		t.Errorf("after DPD, packet went over %x", m)
	}
}

func TestAnyConnectDTLSBlocked(t *testing.T) {
	saved := dtlsTimeout
	dtlsTimeout = time.Second
	defer func() { dtlsTimeout = saved }()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0") // UDP that never answers
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	o := fakeOcserv(t, pc.LocalAddr().(*net.UDPAddr).Port, nil)
	tun, err := AnyConnectTunnel(context.Background(), o, "COOKIE")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if m := echoMark(t, tun); m != 0xee { // at once, over TLS
		t.Errorf("first packet over %x", m)
	}
	time.Sleep(1500 * time.Millisecond)
	if tun.(*acTun).DTLS() {
		t.Error("DTLS up with UDP blocked")
	}
	if m := echoMark(t, tun); m != 0xee {
		t.Errorf("packet over %x, want TLS", m)
	}
}

func TestDTLSOffer(t *testing.T) {
	u, _ := portalURL("vpn.example.com")
	h := http.Header{"X-Dtls-Ciphersuite": {"PSK-NEGOTIATE"}, "X-Dtls-Port": {"443"}, "X-Dtls-App-Id": {"0a0b"}, "X-Dtls-Dpd": {"60"}}
	addr, id, dpd, ok := dtlsOffer(h, u)
	if !ok || addr != "vpn.example.com:443" || string(id) != "\x0a\x0b" || dpd != time.Minute {
		t.Errorf("%s %x %v %v", addr, id, dpd, ok)
	}
	for _, bad := range []http.Header{
		{"X-Dtls-Ciphersuite": {"AES128-SHA"}, "X-Dtls-Port": {"443"}, "X-Dtls-App-Id": {"0a"}}, // legacy only
		{"X-Dtls-Ciphersuite": {"PSK-NEGOTIATE"}, "X-Dtls-App-Id": {"0a"}},                      // no port
		{"X-Dtls-Ciphersuite": {"PSK-NEGOTIATE"}, "X-Dtls-Port": {"443"}, "X-Dtls-App-Id": {"zz"}},
		{"X-Dtls-Ciphersuite": {"PSK-NEGOTIATE"}, "X-Dtls-Port": {"443"}, "X-Dtls-App-Id": {strings.Repeat("ab", 33)}},
	} {
		if _, _, _, ok := dtlsOffer(h0(bad), u); ok {
			t.Errorf("accepted %v", bad)
		}
	}
}

func h0(h http.Header) http.Header {
	out := http.Header{}
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}
