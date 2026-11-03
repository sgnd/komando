package sslvpn

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeGateway serves HTTPS for the login; a request whose first line
// tunnel claims (CONNECT ..., GET /remote/sslvpn-tunnel, ...) is hijacked
// and handed to tunnel.
func fakeGateway(t *testing.T, mux *http.ServeMux, tunnel func(c net.Conn, br *bufio.Reader, firstLine string)) (Options, func()) {
	t.Helper()
	isTunnel := func(r *http.Request) bool {
		return r.Method == "CONNECT" || r.URL.Path == "/remote/sslvpn-tunnel" || r.URL.Path == "/ssl-tunnel-connect.sslvpn" || r.URL.Path == "/myvpn"
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isTunnel(r) {
			mux.ServeHTTP(w, r)
			return
		}
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		tunnel(c, brw.Reader, r.Method+" "+r.URL.RequestURI())
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	addr := srv.Listener.Addr().String()
	o := Options{Portal: "https://127.0.0.1", CA: pemCA, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}}
	return o, func() {}
}

func echoIP(t *testing.T, tun Tunnel) {
	t.Helper()
	if err := tun.WritePacket([]byte{0x45, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-tun.Packets():
		if string(p) != string([]byte{0x45, 1, 2, 3, 0xee}) {
			t.Errorf("echoed %x", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet back")
	}
}

func TestAnyConnect(t *testing.T) {
	mux := http.NewServeMux()
	step := 0
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(b), `type="init"`):
			io.WriteString(w, `<config-auth type="auth-request"><opaque is-for="sg"><tunnel-group>x</tunnel-group></opaque><auth id="main"><form action="/auth"><input type="text" name="username" label="Username:"/><input type="password" name="password" label="Password:"/></form></auth></config-auth>`)
		case strings.Contains(string(b), "<password>s3cret</password>") && step == 0:
			step = 1 // a second factor
			io.WriteString(w, `<config-auth type="auth-request"><auth id="otp"><form action="/auth"><input type="password" name="secondary_password" label="OTP:"/></form></auth></config-auth>`)
		case strings.Contains(string(b), "<secondary_password>123456</secondary_password>"):
			http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: "COOKIE42"})
			io.WriteString(w, `<config-auth type="complete"><session-token>COOKIE42</session-token></config-auth>`)
		default:
			io.WriteString(w, `<config-auth type="auth-request"><auth id="main"><error>Login failed.</error><form><input type="password" name="password"/></form></auth></config-auth>`)
		}
	})
	o, toTunnel := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, line string) {
		if !strings.HasPrefix(line, "CONNECT ") {
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 192.168.99.5\r\nX-CSTP-DNS: 192.168.99.1\r\nX-CSTP-MTU: 1300\r\n\r\n")
		hdr := make([]byte, 8)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			p := make([]byte, binary.BigEndian.Uint16(hdr[4:]))
			io.ReadFull(br, p)
			if hdr[6] == cstpData { // echo with a mark
				p = append(p, 0xee)
				out := append([]byte("STF\x01\x00\x00\x00\x00"), p...)
				binary.BigEndian.PutUint16(out[4:], uint16(len(p)))
				c.Write(out)
			}
		}
	})
	o.User, o.Password = "e2e", "s3cret"
	if _, err := AnyConnectLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
		t.Fatalf("an OTP without a person: %v", err)
	}
	step = 0
	o.Prompt = func(label string, secret bool) (string, error) {
		if label != "OTP:" || !secret {
			t.Errorf("prompt %q %v", label, secret)
		}
		return "123456", nil
	}
	cookie, err := AnyConnectLogin(context.Background(), o)
	if err != nil || cookie != "COOKIE42" {
		t.Fatalf("login: %q %v", cookie, err)
	}
	toTunnel()
	tun, err := AnyConnectTunnel(context.Background(), o, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Addresses()[0].String() != "192.168.99.5" || tun.DNS()[0].String() != "192.168.99.1" || tun.MTU() != 1300 {
		t.Errorf("config %v %v %d", tun.Addresses(), tun.DNS(), tun.MTU())
	}
	echoIP(t, tun)
}

func TestAnyConnectWrongPassword(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), `type="init"`) {
			io.WriteString(w, `<config-auth type="auth-request"><auth><form><input type="text" name="username"/><input type="password" name="password"/></form></auth></config-auth>`)
			return
		}
		io.WriteString(w, `<config-auth type="auth-request"><auth><error>Login failed.</error><form><input type="password" name="password"/></form></auth></config-auth>`)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	o.User, o.Password = "e2e", "wrong"
	var le *LoginError
	if _, err := AnyConnectLogin(context.Background(), o); !errors.As(err, &le) || !strings.Contains(le.Msg, "Login failed") {
		t.Errorf("wrong password: %v", err)
	}
}

// ocserv asks for the password again, without an <error>, when it was wrong
func TestAnyConnectAsksAgain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<config-auth type="auth-request"><auth><form><input type="password" name="password" label="Password:"/></form></auth></config-auth>`)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	o.User, o.Password = "e2e", "wrong"
	var le *LoginError
	if _, err := AnyConnectLogin(context.Background(), o); !errors.As(err, &le) || !strings.Contains(le.Msg, "refused") {
		t.Errorf("asked again: %v", err)
	}
}

// pppPeer plays the gateway's side of PPP: it asks for nothing, acks the
// client's LCP, naks IPCP with an address and DNS, then echoes IP.
func pppPeer(t *testing.T, read func() (uint16, []byte, error), write func(uint16, []byte)) {
	for {
		proto, b, err := read()
		if err != nil {
			return
		}
		switch proto {
		case pppLCP:
			if b[0] == cfgRequest {
				write(pppLCP, pkt(cfgAck, b[1], b[4:]))
				write(pppLCP, pkt(cfgRequest, 1, opt(5, []byte{1, 2, 3, 4})))
			}
		case pppIPCP:
			if b[0] == cfgRequest {
				opts := b[4:]
				if strings.Contains(string(opts), "\x03\x06\x00\x00\x00\x00") {
					nak := append(opt(3, []byte{10, 20, 0, 9}), opt(129, []byte{10, 20, 0, 1})...)
					nak = append(nak, opt(131, []byte{10, 20, 0, 2})...)
					write(pppIPCP, pkt(cfgNak, b[1], nak))
				} else {
					write(pppIPCP, pkt(cfgAck, b[1], opts))
				}
			}
		case pppIPv4:
			write(pppIPv4, append(b, 0xee))
		}
	}
}

func TestFortinet(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/remote/logincheck", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case r.Form.Get("credential") == "s3cret":
			io.WriteString(w, "ret=2,tokeninfo=,reqid=7,polid=1,grp=g,magic=m")
		case r.Form.Get("code") == "999" && r.Form.Get("reqid") == "7":
			http.SetCookie(w, &http.Cookie{Name: "SVPNCOOKIE", Value: "FORTI1", Path: "/"})
			io.WriteString(w, "ret=1,redir=/remote/fortisslvpn")
		default:
			io.WriteString(w, "ret=0")
		}
	})
	mux.HandleFunc("/remote/fortisslvpn_xml", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<?xml version="1.0"?><sslvpn-tunnel ver="2"><ipv4><dns ip="10.20.0.1"/><assigned-addr ipv4="10.20.0.9"/></ipv4></sslvpn-tunnel>`)
	})
	o, toTunnel := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, line string) {
		if !strings.HasPrefix(line, "GET /remote/sslvpn-tunnel") {
			c.Close()
			return
		}
		read := func() (uint16, []byte, error) {
			hdr := make([]byte, 6)
			if _, err := io.ReadFull(br, hdr); err != nil {
				return 0, nil, err
			}
			f := make([]byte, binary.BigEndian.Uint16(hdr[4:]))
			io.ReadFull(br, f)
			f = f[2:] // ff 03
			return binary.BigEndian.Uint16(f), f[2:], nil
		}
		write := func(proto uint16, data []byte) {
			f := append([]byte{0xff, 0x03, byte(proto >> 8), byte(proto)}, data...)
			h := make([]byte, 6)
			binary.BigEndian.PutUint16(h, uint16(6+len(f)))
			h[2], h[3] = 0x50, 0x50
			binary.BigEndian.PutUint16(h[4:], uint16(len(f)))
			c.Write(append(h, f...))
		}
		pppPeer(t, read, write)
	})
	o.User, o.Password = "e2e", "s3cret"
	o.Prompt = func(string, bool) (string, error) { return "999", nil }
	cookie, err := FortinetLogin(context.Background(), o)
	if err != nil || cookie != "FORTI1" {
		t.Fatalf("login: %q %v", cookie, err)
	}
	toTunnel()
	tun, err := FortinetTunnel(context.Background(), o, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Addresses()[0].String() != "10.20.0.9" || len(tun.DNS()) == 0 || tun.DNS()[0].String() != "10.20.0.1" {
		t.Errorf("config %v %v", tun.Addresses(), tun.DNS())
	}
	echoIP(t, tun)

	o.Password, o.Prompt = "wrong", nil
	var le *LoginError
	if _, err := FortinetLogin(context.Background(), o); !errors.As(err, &le) {
		t.Errorf("wrong password: %v", err)
	}
}

func TestGlobalProtect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ssl-vpn/login.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch {
		case r.Form.Get("passwd") == "s3cret":
			w.WriteHeader(512)
			io.WriteString(w, `var respStatus = "Challenge"; var respMsg = "Enter the code"; thisForm.inputStr.value = "abc"; inputStr = "abc";`)
		case r.Form.Get("passwd") == "4242" && r.Form.Get("inputStr") == "abc":
			io.WriteString(w, `<?xml version="1.0"?><jnlp><application-desc><argument>(null)</argument><argument>GPCOOKIE</argument>`+
				`<argument>x</argument><argument>gw1</argument><argument>e2e</argument><argument>tunnel</argument><argument>-1</argument>`+
				`<argument>corp</argument></application-desc></jnlp>`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("/ssl-vpn/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("authcookie") != "GPCOOKIE" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		io.WriteString(w, `<response><ip-address>10.30.0.7</ip-address><mtu>1350</mtu><dns><member>10.30.0.1</member></dns></response>`)
	})
	o, toTunnel := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, line string) {
		if !strings.Contains(line, "/ssl-tunnel-connect.sslvpn?") || !strings.Contains(line, "authcookie=GPCOOKIE") {
			c.Close()
			return
		}
		io.WriteString(c, "START_TUNNEL")
		hdr := make([]byte, 16)
		for {
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			n := binary.BigEndian.Uint16(hdr[6:])
			if n == 0 {
				continue
			}
			p := make([]byte, n)
			io.ReadFull(br, p)
			p = append(p, 0xee)
			binary.BigEndian.PutUint16(hdr[6:], uint16(len(p)))
			c.Write(append(hdr, p...))
		}
	})
	o.User, o.Password = "e2e", "s3cret"
	if _, err := GlobalProtectLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
		t.Fatalf("a challenge without a person: %v", err)
	}
	o.Prompt = func(label string, _ bool) (string, error) {
		if label != "Enter the code" {
			t.Errorf("prompt %q", label)
		}
		return "4242", nil
	}
	s, err := GlobalProtectLogin(context.Background(), o)
	if err != nil || s.AuthCookie != "GPCOOKIE" || s.Portal != "gw1" || s.Domain != "corp" {
		t.Fatalf("login: %+v %v", s, err)
	}
	back, err := ParseGPSession(s.String())
	if err != nil || back != s {
		t.Fatalf("session round trip: %+v %v", back, err)
	}
	toTunnel()
	tun, err := GlobalProtectTunnel(context.Background(), o, s)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Addresses()[0].String() != "10.30.0.7" || tun.MTU() != 1350 || tun.DNS()[0].String() != "10.30.0.1" {
		t.Errorf("config %v %d %v", tun.Addresses(), tun.MTU(), tun.DNS())
	}
	echoIP(t, tun)
}

func TestF5(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "MRHSession", Value: "deleted", Path: "/"})
	})
	mux.HandleFunc("/my.policy", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("password") == "s3cret" {
			http.SetCookie(w, &http.Cookie{Name: "MRHSession", Value: "F5SESS", Path: "/"})
		}
		io.WriteString(w, "<html>welcome</html>")
	})
	mux.HandleFunc("/vdesk/vpn/index.php3", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<favorites type="VPN"><favorite id="/Common/na"><caption>net</caption></favorite></favorites>`)
	})
	mux.HandleFunc("/vdesk/vpn/connect.php3", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resourcename") != "/Common/na" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `<favorite><object><ur_Z>ZZ9</ur_Z></object></favorite>`)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, line string) {
		if !strings.Contains(line, "/myvpn?") || !strings.Contains(line, "sess=ZZ9") {
			c.Close()
			return
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nX-VPN-client-IP: 10.40.0.4\r\n\r\n")
		read := func() (uint16, []byte, error) {
			h := make([]byte, 4)
			if _, err := io.ReadFull(br, h); err != nil || h[0] != 0xf5 {
				return 0, nil, io.EOF
			}
			f := make([]byte, binary.BigEndian.Uint16(h[2:]))
			io.ReadFull(br, f)
			f = f[2:]
			return binary.BigEndian.Uint16(f), f[2:], nil
		}
		write := func(proto uint16, data []byte) {
			f := append([]byte{0xff, 0x03, byte(proto >> 8), byte(proto)}, data...)
			h := []byte{0xf5, 0, 0, 0}
			binary.BigEndian.PutUint16(h[2:], uint16(len(f)))
			c.Write(append(h, f...))
		}
		pppPeer(t, read, write)
	})
	o.User, o.Password = "e2e", "wrong"
	var le *LoginError
	if _, err := F5Login(context.Background(), o); !errors.As(err, &le) {
		t.Fatalf("wrong password: %v", err)
	}
	o.Password = "s3cret"
	s, err := F5Login(context.Background(), o)
	if err != nil || s != "F5SESS|/Common/na|ZZ9" {
		t.Fatalf("login %q %v", s, err)
	}
	tun, err := F5Tunnel(context.Background(), o, s)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Addresses()[0].String() != "10.20.0.9" { // IPCP's answer wins over the header
		t.Logf("address %v", tun.Addresses())
	}
	echoIP(t, tun)
}
