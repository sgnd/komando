package sslvpn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake Pulse Connect Secure server, written from the protocol: it builds
// and checks every byte itself (its own helpers, not the client's), so the
// client is checked against the layout, not against its own code.

type fakePulseCfg struct {
	realms   []string // realm choices; more than one needs a person
	j5       bool     // the 2021 password question (Juniper type 5)
	gtc      bool     // a one-time code after the password
	failText string   // refuse the password with this text (0xc5)
	esp      bool     // offer ESP keys
	fatalOn  byte     // a data packet starting with this byte gets a fatal error back
}

type fakePulse struct {
	t   *testing.T
	cfg fakePulseCfg
	mu  sync.Mutex
	got map[string]string // what the client sent: user, password, realm, code, logout, esp
}

const fakeCookie = "cccccccccccccccccccccccccccccccc"

func (f *fakePulse) set(k, v string) { f.mu.Lock(); f.got[k] = v; f.mu.Unlock() }
func (f *fakePulse) get(k string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got[k]
}

func startFakePulse(t *testing.T, cfg fakePulseCfg) (*fakePulse, Options) {
	t.Helper()
	f := &fakePulse{t: t, cfg: cfg, got: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Upgrade") != "IF-T/TLS 1.0" || r.Header.Get("Content-Type") != "EAP" || r.URL.Path != "/sales" {
			t.Errorf("upgrade request %s %s %v", r.Method, r.URL.Path, r.Header)
			w.WriteHeader(400)
			return
		}
		cookie := ""
		if ck, err := r.Cookie("DSID"); err == nil {
			cookie = ck.Value
		}
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
		f.serve(&fakeIFT{c: c, br: brw.Reader}, cookie)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return f, Options{Portal: "https://" + srv.Listener.Addr().String() + "/sales", User: "ana",
		CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
}

type fakeIFT struct {
	c       net.Conn
	br      *bufio.Reader
	lastSeq int64
}

// msg reads one IF-T message and checks the client's counter goes up by one.
func (x *fakeIFT) msg() (vendor, typ uint32, body []byte, err error) {
	h := make([]byte, 16)
	if _, err = io.ReadFull(x.br, h); err != nil {
		return
	}
	if h[0] != 0 {
		return 0, 0, nil, errors.New("reserved byte set")
	}
	vendor, typ = binary.BigEndian.Uint32(h)&0xffffff, binary.BigEndian.Uint32(h[4:])
	n := binary.BigEndian.Uint32(h[8:])
	if seq := int64(binary.BigEndian.Uint32(h[12:])); seq != x.lastSeq+1 {
		return 0, 0, nil, errors.New("message counter skipped")
	} else {
		x.lastSeq = seq
	}
	body = make([]byte, n-16)
	_, err = io.ReadFull(x.br, body)
	return
}

// put writes one message, split into small writes (1, 2, 4... bytes) so
// the client must put it together again.
func (x *fakeIFT) put(vendor, typ uint32, body []byte) {
	b := make([]byte, 16, 16+len(body))
	binary.BigEndian.PutUint32(b, vendor)
	binary.BigEndian.PutUint32(b[4:], typ)
	binary.BigEndian.PutUint32(b[8:], uint32(16+len(body)))
	b = append(b, body...)
	for n := 1; len(b) > 0; n *= 2 {
		k := min(n, len(b))
		x.c.Write(b[:k])
		b = b[k:]
	}
}

// fake AVP and EAP layouts, by hand
func fAVP(code uint32, data []byte) []byte { // Juniper vendor AVP
	b := []byte{byte(code >> 24), byte(code >> 16), byte(code >> 8), byte(code), 0x80, 0, 0, 0, 0, 0, 0x05, 0x83}
	l := 12 + len(data)
	b[5], b[6], b[7] = byte(l>>16), byte(l>>8), byte(l)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func fEAPMsg(inner []byte) []byte { // AVP 79, no vendor
	l := 8 + len(inner)
	b := append([]byte{0, 0, 0, 79, 0, byte(l >> 16), byte(l >> 8), byte(l)}, inner...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func fExp(code, id byte, vt byte, data []byte) []byte { // expanded Juniper EAP
	b := append([]byte{code, id, 0, 0, 0xfe, 0, 0x0a, 0x4c, 0, 0, 0, vt}, data...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

var juniper1 = []byte{0, 0x0a, 0x4c, 0x01}

func (f *fakePulse) challenge(x *fakeIFT, eap []byte) {
	x.put(0x5597, 5, append(append([]byte{}, juniper1...), eap...))
}

// response reads a client auth response and returns its EAP packet.
func (f *fakePulse) response(x *fakeIFT) []byte {
	v, typ, b, err := x.msg()
	if err != nil {
		return nil
	}
	if v != 0x5597 || typ != 6 || !bytes.Equal(b[:4], juniper1) {
		f.t.Errorf("auth response %#x/%d %x", v, typ, b)
		return nil
	}
	eap := b[4:]
	if int(binary.BigEndian.Uint16(eap[2:])) != len(eap) {
		f.t.Errorf("EAP length %x", eap)
	}
	return eap
}

// avps splits a client's expanded Juniper/1 response (id) into AVPs.
func (f *fakePulse) avps(eap []byte, id byte) map[uint32][]byte {
	if eap == nil { // the client hung up
		return nil
	}
	if len(eap) < 12 || eap[0] != 2 || eap[1] != id || !bytes.Equal(eap[4:12], []byte{0xfe, 0, 0x0a, 0x4c, 0, 0, 0, 1}) {
		f.t.Errorf("not an expanded Juniper/1 response to %d: %x", id, eap)
		return nil
	}
	out := map[uint32][]byte{}
	b := eap[12:]
	for len(b) >= 8 {
		code := binary.BigEndian.Uint32(b)
		l := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		hdr := 8
		if b[4]&0x80 != 0 {
			hdr = 12
			if binary.BigEndian.Uint32(b[8:]) != 0x583 {
				f.t.Errorf("AVP %#x vendor %x", code, b[8:12])
			}
		} else if code != 79 || b[4] != 0x40 {
			f.t.Errorf("AVP %#x flags %#x", code, b[4])
		}
		out[code] = b[hdr:l]
		b = b[(l+3)/4*4:]
	}
	return out
}

func (f *fakePulse) serve(x *fakeIFT, cookie string) {
	x.lastSeq = -1
	if v, typ, b, err := x.msg(); err != nil || v != 0x5597 || typ != 1 || !bytes.Equal(b, []byte{0, 1, 2, 2}) {
		f.t.Errorf("version request %#x/%d %x %v", v, typ, b, err)
		return
	}
	x.put(0x5597, 2, []byte{0, 0, 0, 2})
	if v, typ, b, _ := x.msg(); v != 0x0a4c || typ != 0x88 || !bytes.HasPrefix(b, []byte("clientHostName=")) || !bytes.HasSuffix(b, []byte("\n\x00")) {
		f.t.Errorf("client info %#x/%#x %q", v, typ, b)
		return
	}
	x.put(0x5597, 5, juniper1) // start the login
	if eap := f.response(x); !bytes.Equal(eap, []byte("\x02\x01\x00\x0e\x01anonymous")) {
		f.t.Errorf("identity %q", eap)
		return
	}
	f.challenge(x, fExp(1, 2, 1, fAVP(0xd49, []byte{0, 0, 0, 3}))) // server info
	a := f.avps(f.response(x), 2)
	if string(a[0xd5e]) == "" || !strings.HasPrefix(string(a[0xd70]), "Pulse-Secure/") {
		f.t.Errorf("client info AVPs %v", a)
	}
	resume := string(a[0xd53])
	if cookie != "" && resume != cookie {
		f.t.Errorf("tunnel cookie %q in AVP, %q in the header", resume, cookie)
	}
	id := byte(3)
	if resume == "" || resume != fakeCookie {
		if !f.login(x, &id, resume != "") {
			return
		}
	}
	f.challenge(x, fExp(1, id, 1, fAVP(0xd53, []byte(fakeCookie))))
	if eap := f.response(x); !bytes.Equal(eap, []byte{2, id, 0, 12, 0xfe, 0, 0x0a, 0x4c, 0, 0, 0, 1}) {
		f.t.Errorf("answer to the cookie %x", eap)
		return
	}
	x.put(0x5597, 7, append(append([]byte{}, juniper1...), 3, id, 0, 4))
	if resume == fakeCookie {
		f.tunnel(x)
	} else {
		x.c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, _, err := x.msg(); err == nil {
			f.t.Error("the login connection should close after the cookie")
		}
	}
}

// login asks for the realm, the password and the code; false: it ended.
func (f *fakePulse) login(x *fakeIFT, id *byte, staleCookie bool) bool {
	if len(f.cfg.realms) > 0 && !staleCookie {
		var b []byte
		for _, r := range f.cfg.realms {
			b = append(b, fAVP(0xd4e, []byte(r))...)
		}
		f.challenge(x, fExp(1, *id, 1, b))
		a := f.avps(f.response(x), *id)
		if a == nil {
			return false
		}
		f.set("realm", string(a[0xd50]))
		*id++
	}
	// the password, in its inner EAP
	q := fExp(1, 10, 2, []byte{0x01})
	if f.cfg.j5 {
		q = fExp(1, 10, 5, []byte{0x01, 0, 0, 0, 0, 0})
	}
	f.challenge(x, fExp(1, *id, 1, append(fAVP(0xd81, []byte("Corp password")), fEAPMsg(q)...)))
	resp := f.response(x)
	if resp == nil {
		return false
	}
	a := f.avps(resp, *id)
	*id++
	if len(a) != 2 {
		f.t.Errorf("password answer has %d AVPs, want user name and EAP", len(a))
	}
	f.set("user", string(a[0xd6d]))
	in := a[79]
	switch {
	case f.cfg.j5:
		if len(in) != 31 || !bytes.Equal(in[:12], []byte{2, 10, 0, 31, 0xfe, 0, 0x0a, 0x4c, 0, 0, 0, 5}) || in[12] != 1 {
			f.t.Errorf("type 5 password answer %x", in)
			return false
		}
		f.set("password", string(bytes.TrimRight(in[13:], "\x00")))
	default:
		if len(in) < 15 || !bytes.Equal(in[:12], []byte{2, 10, in[2], in[3], 0xfe, 0, 0x0a, 0x4c, 0, 0, 0, 2}) || in[12] != 2 || in[13] != 2 ||
			int(in[14]) != len(in)-13 || int(binary.BigEndian.Uint16(in[2:])) != len(in) {
			f.t.Errorf("type 2 password answer %x", in)
			return false
		}
		f.set("password", string(in[15:]))
	}
	if f.cfg.failText != "" {
		txt := []byte(f.cfg.failText)
		f.challenge(x, fExp(1, *id, 1, fEAPMsg(fExp(1, 11, 2, append([]byte{0xc5, 1, byte(len(txt) + 2)}, txt...)))))
		return false
	}
	if f.get("password") != "s3cret" {
		f.challenge(x, fExp(1, *id, 1, fEAPMsg(fExp(1, 11, 2, []byte{0x81}))))
		return false
	}
	if f.cfg.gtc {
		g := []byte{1, 12, 0, 0, 6}
		g = append(g, "Enter SecurID PASSCODE"...)
		binary.BigEndian.PutUint16(g[2:], uint16(len(g)))
		f.challenge(x, fExp(1, *id, 1, fEAPMsg(g)))
		a := f.avps(f.response(x), *id)
		*id++
		if a == nil {
			return false
		}
		in := a[79]
		if len(in) < 5 || in[0] != 2 || in[1] != 12 || in[4] != 6 || int(binary.BigEndian.Uint16(in[2:])) != len(in) {
			f.t.Errorf("GTC answer %x", in)
			return false
		}
		f.set("code", string(in[5:]))
	}
	return true
}

// config builds a Juniper type 1 body (after the IF-T header) of kind.
func fConfig(kind uint32, rest []byte) []byte {
	b := make([]byte, 0x1c, 0x1c+len(rest))
	binary.BigEndian.PutUint32(b[0x10:], kind)
	b = append(b, rest...)
	binary.BigEndian.PutUint32(b[0x18:], uint32(len(b)))
	return b
}

func tlv(typ uint16, v []byte) []byte {
	return append([]byte{byte(typ >> 8), byte(typ), byte(len(v) >> 8), byte(len(v))}, v...)
}

func (f *fakePulse) tunnel(x *fakeIFT) {
	pre := append([]byte{0x2c, 0x00, 0, 13, 3, 0, 0, 0}, tlv(0x4026, []byte{0})...)
	routes := []byte{0x2e, 0x00, 0, 24, 1, 0, 0, 0, 0x07, 0, 0, 0x10, 0, 0, 0xff, 0xff, 10, 0, 0, 0, 10, 0, 255, 255}
	var attrs []byte
	attrs = append(attrs, tlv(0x0001, []byte{192, 168, 77, 5})...)
	attrs = append(attrs, tlv(0x0002, []byte{255, 255, 255, 0})...)
	attrs = append(attrs, tlv(0x0003, []byte{192, 168, 77, 1})...)
	attrs = append(attrs, tlv(0x4006, []byte("corp.example\x00"))...)
	attrs = append(attrs, tlv(0x4005, []byte{0, 0, 0x05, 0x14})...) // 1300
	attrs = append(attrs, tlv(0x4016, []byte{0x11, 0x94})...)
	sect := make([]byte, 8, 8+len(attrs))
	binary.BigEndian.PutUint32(sect, uint32(8+len(attrs)))
	binary.BigEndian.PutUint32(sect[4:], 0x03000000)
	sect = append(sect, attrs...)
	x.put(0x0a4c, 1, fConfig(0x2e20f000, append(append(pre, routes...), sect...)))
	if f.cfg.esp {
		esp := make([]byte, 8+0x46)                       // length, 0x01000000, SPI, 0x40, 64 bytes of keys
		binary.BigEndian.PutUint32(esp, uint32(len(esp))) // the message length less 0x2c
		binary.BigEndian.PutUint32(esp[4:], 0x01000000)
		binary.LittleEndian.PutUint32(esp[8:], 0x12345678)
		binary.BigEndian.PutUint16(esp[12:], 0x40)
		copy(esp[14:], bytes.Repeat([]byte("e"), 16))
		copy(esp[30:], bytes.Repeat([]byte("h"), 20))
		x.put(0x0a4c, 1, fConfig(0x21202400, esp))
		v, typ, r, err := x.msg()
		if err != nil || v != 0x0a4c || typ != 1 || len(r) != 0xc0-16 || binary.BigEndian.Uint32(r[0x10:]) != 0x21202400 ||
			binary.BigEndian.Uint32(r[0x18:]) != 0xb0 || binary.BigEndian.Uint32(r[0x1c:]) != 0x94 ||
			binary.BigEndian.Uint32(r[0x20:]) != 0x01000000 || binary.BigEndian.Uint16(r[0x28:]) != 0x40 || !bytes.Equal(r[0x24+0x46:], esp[8:]) {
			f.t.Errorf("ESP answer %x", r)
			return
		}
		if v, typ, b, _ := x.msg(); v != 0x0a4c || typ != 5 || string(b) != "ncmo=1\n\x00" {
			f.t.Errorf("after the ESP answer %#x/%d %q", v, typ, b)
			return
		}
		f.set("esp", "answered")
	}
	x.put(0x0a4c, 0x8f, []byte{0, 0, 0, 0})
	for {
		v, typ, b, err := x.msg()
		if err != nil {
			return
		}
		switch {
		case v == 0x0a4c && typ == 0x89:
			f.set("logout", "yes")
			return
		case v == 0x0a4c && typ == 4:
			if f.cfg.fatalOn != 0 && len(b) > 0 && b[0] == f.cfg.fatalOn {
				x.put(0x0a4c, 0x93, []byte("errorType=7 errorString=Session%20terminated\n"))
				return
			}
			x.put(0x0a4c, 4, append(b, 0xee))
		}
	}
}

func TestPulseLogin(t *testing.T) {
	f, o := startFakePulse(t, fakePulseCfg{realms: []string{"Users", "Admins"}, gtc: true})
	o.Password = "s3cret"
	var asked []string
	o.Prompt = func(label string, secret bool) (string, error) {
		asked = append(asked, label)
		if strings.HasSuffix(label, "Realm (number or name)") {
			return "2", nil
		}
		return "123456", nil
	}
	cookie, err := PulseLogin(context.Background(), o)
	if err != nil || cookie != fakeCookie {
		t.Fatalf("login: %q %v", cookie, err)
	}
	if f.get("realm") != "Admins" || f.get("user") != "ana" || f.get("password") != "s3cret" || f.get("code") != "123456" {
		t.Errorf("server saw %v", f.got)
	}
	if len(asked) != 2 || asked[0] != "The VPN offers more than one realm:\n  1  Users\n  2  Admins\nRealm (number or name)" || asked[1] != "Enter SecurID PASSCODE" {
		t.Errorf("asked %q", asked)
	}
}

// A person answers a choice with its number or its name, in any case, and
// a wrong answer is asked again, up to 3 times.
func TestPulseChoose(t *testing.T) {
	opts := []string{"Users", "Admins", "admins-eu"}
	cases := []struct {
		answers []string
		want    string
		asked   int
	}{
		{[]string{"2"}, "Admins", 1},
		{[]string{" Admins "}, "Admins", 1},
		{[]string{"users"}, "Users", 1},
		{[]string{"ADMINS-EU"}, "admins-eu", 1},
		{[]string{"4", "admin", "3"}, "admins-eu", 3},
		{[]string{"", "x", "0"}, "", 3},
	}
	for _, c := range cases {
		var asked []string
		s := &pulseSession{o: Options{Prompt: func(label string, secret bool) (string, error) {
			asked = append(asked, label)
			return c.answers[len(asked)-1], nil
		}}}
		got, err := s.choose("Realm", opts)
		var le *LoginError
		switch {
		case c.want == "" && !errors.As(err, &le):
			t.Errorf("%q: want a login error, got %q %v", c.answers, got, err)
		case c.want != "" && (err != nil || got != c.want):
			t.Errorf("%q: got %q %v, want %q", c.answers, got, err, c.want)
		}
		if len(asked) != c.asked {
			t.Errorf("%q: asked %d times, want %d", c.answers, len(asked), c.asked)
		}
		if len(asked) > 1 && asked[1] != "Not one of the choices.\nRealm (number or name)" {
			t.Errorf("%q: asked again with %q", c.answers, asked[1])
		}
	}
	// a stop at the question (Ctrl-C) ends the choice at once
	s := &pulseSession{o: Options{Prompt: func(string, bool) (string, error) { return "", context.Canceled }}}
	if _, err := s.choose("Realm", opts); !errors.Is(err, context.Canceled) {
		t.Errorf("Ctrl-C: %v", err)
	}
}

// The sign-in notice takes y or yes in any case; anything else refuses it.
func TestPulseBanner(t *testing.T) {
	for a, ok := range map[string]bool{"y": true, "Y": true, "yes": true, " YES ": true, "": false, "n": false, "ok": false} {
		var label string
		s := &pulseSession{o: Options{Prompt: func(l string, secret bool) (string, error) { label = l; return a, nil }}}
		_, err := s.banner("Authorized use only.\n")
		if (err == nil) != ok {
			t.Errorf("%q: %v", a, err)
		}
		if label != "Authorized use only.\nAccept the sign-in notice? [y/N]" {
			t.Errorf("asked %q", label)
		}
	}
}

func TestPulseOneRealmNoPerson(t *testing.T) {
	f, o := startFakePulse(t, fakePulseCfg{realms: []string{"Users"}})
	o.Password = "s3cret"
	if c, err := PulseLogin(context.Background(), o); err != nil || c != fakeCookie || f.get("realm") != "Users" {
		t.Fatalf("login %q %v %v", c, err, f.got)
	}
}

func TestPulseNeedsPerson(t *testing.T) {
	for _, cfg := range []fakePulseCfg{{realms: []string{"Users", "Admins"}}, {gtc: true}} {
		_, o := startFakePulse(t, cfg)
		o.Password = "s3cret"
		if _, err := PulseLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
			t.Errorf("%+v without a person: %v", cfg, err)
		}
	}
	_, o := startFakePulse(t, fakePulseCfg{}) // no stored password
	if _, err := PulseLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
		t.Errorf("no password, no person: %v", err)
	}
}

func TestPulseRefused(t *testing.T) {
	_, o := startFakePulse(t, fakePulseCfg{})
	o.Password = "wrong"
	var le *LoginError
	if _, err := PulseLogin(context.Background(), o); !errors.As(err, &le) || !strings.Contains(err.Error(), "wrong user name or password") {
		t.Errorf("wrong password: %v", err)
	}
	_, o = startFakePulse(t, fakePulseCfg{failText: "Account disabled"})
	o.Password = "s3cret"
	if _, err := PulseLogin(context.Background(), o); !errors.As(err, &le) || !strings.HasSuffix(err.Error(), ": Account disabled") {
		t.Errorf("refused with a reason: %v", err)
	}
}

func TestPulseType5Password(t *testing.T) {
	f, o := startFakePulse(t, fakePulseCfg{j5: true})
	o.Password = "s3cret"
	if _, err := PulseLogin(context.Background(), o); err != nil || f.get("password") != "s3cret" {
		t.Fatalf("type 5: %v %v", err, f.got)
	}
}

func TestPulseTunnel(t *testing.T) {
	f, o := startFakePulse(t, fakePulseCfg{esp: true, fatalOn: 0x99})
	tun, err := PulseTunnel(context.Background(), o, fakeCookie)
	if err != nil {
		t.Fatal(err)
	}
	if f.get("esp") != "answered" {
		t.Error("ESP keys not answered")
	}
	if tun.Addresses()[0].String() != "192.168.77.5" || tun.DNS()[0].String() != "192.168.77.1" || tun.MTU() != 1300 {
		t.Errorf("config %v %v %d", tun.Addresses(), tun.DNS(), tun.MTU())
	}
	echoIP(t, tun)
	big := bytes.Repeat([]byte{0x45}, 1300)
	tun.WritePacket(big)
	select {
	case p := <-tun.Packets():
		if len(p) != 1301 {
			t.Errorf("big packet came back with %d bytes", len(p))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no big packet back")
	}
	tun.Close()
	for i := 0; i < 30 && f.get("logout") == ""; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if f.get("logout") != "yes" {
		t.Error("Close did not log out")
	}

	tun, err = PulseTunnel(context.Background(), o, fakeCookie)
	if err != nil {
		t.Fatal(err)
	}
	tun.WritePacket([]byte{0x99})
	select {
	case <-tun.Done():
		if !strings.Contains(tun.Err().Error(), "ended the session") {
			t.Errorf("fatal error: %v", tun.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the session did not end")
	}
}

func TestPulseStaleCookie(t *testing.T) {
	_, o := startFakePulse(t, fakePulseCfg{})
	var le *LoginError
	if _, err := PulseTunnel(context.Background(), o, "expired"); !errors.As(err, &le) || !strings.Contains(err.Error(), "session cookie") {
		t.Errorf("stale cookie: %v", err)
	}
}

func FuzzPulseParsers(f *testing.F) {
	f.Add(fAVP(0xd53, []byte(fakeCookie)))
	f.Add(fExp(1, 2, 1, fAVP(0xd49, []byte{0, 0, 0, 3})))
	f.Add(fConfig(0x2e20f000, []byte{0x2c, 0, 0, 8, 3, 0, 0, 0, 0x2e, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 8, 3, 0, 0, 0}))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseAVPs(b)
		parseEAP(b)
		pulseFatal(b)
		if kind, err := configKind(b); err == nil {
			s := &pulseSession{}
			s.mainConfig(b, kind)
		}
	})
}
