package openvpn

import (
	"crypto/rand"
	"crypto/tls"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- a client with an established key, on an in-memory transport --------

type memTransport struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func (m *memTransport) Read() ([]byte, error) {
	select {
	case p := <-m.in:
		return p, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *memTransport) Write(p []byte) error {
	select {
	case m.out <- append([]byte{}, p...):
	default:
	}
	return nil
}

func (m *memTransport) Close() error { m.once.Do(func() { close(m.done) }); return nil }

type lab struct {
	c      *Client
	tr     *memTransport
	sid    [8]byte // the real server's session id
	server dataCipher
	spid   uint32
}

// newLab is a client whose key kid is up (TLS done, data cipher set).
func newLab(t *testing.T, kid byte) *lab {
	t.Helper()
	cfg := &Config{CA: newPKI(t).caPEM, Ciphers: []string{"AES-256-GCM"}, Auth: "SHA256", KeyDirection: -1, TunMTU: 1500}
	tr := &memTransport{in: make(chan []byte, 64), out: make(chan []byte, 256), done: make(chan struct{})}
	c := &Client{cfg: cfg, tr: tr, wrap: plainWrap{}, Packets: make(chan []byte, 256), done: make(chan struct{})}
	l := &lab{c: c, tr: tr}
	copy(l.sid[:], "REALSRV!")
	rand.Read(c.localSID[:])
	c.remoteSID, c.remoteSet = l.sid, true
	c.lastIn.Store(time.Now().UnixNano())
	material := make([]byte, 256)
	rand.Read(material)
	dc, _ := newDataCipher("AES-256-GCM", "SHA256", material)
	ssend, srecv := keyPair(material, 1)
	l.server, _ = newAEAD("AES-256-GCM", ssend, srecv)
	ks := c.newKey(kid)
	ks.data, ks.pending, ks.expect = dc, false, 3
	c.cur = ks
	c.pushed = Pushed{PeerID: -1, Cipher: "AES-256-GCM", Ping: 10 * time.Second, PingRestart: 120 * time.Second, MTU: 1500}
	go c.readLoop()
	t.Cleanup(func() { c.Close() })
	return l
}

func (l *lab) ctrl(op, kid byte, sid [8]byte, b ctrlBody) {
	l.tr.in <- plainWrap{}.wrap(op<<3|kid, sid, encodeBody(b))
}

func (l *lab) data(kid byte, payload string) {
	l.spid++
	ad := []byte{opDataV2<<3 | kid, 0, 0, 1}
	l.tr.in <- append(append([]byte{}, ad...), l.server.seal(l.spid, ad, []byte(payload))...)
}

// settle lets the read loop take what was sent.
func (l *lab) settle() {
	for i := 0; i < 100 && len(l.tr.in) > 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
}

func (l *lab) key(id byte) *keyState {
	l.c.mu.Lock()
	defer l.c.mu.Unlock()
	return l.c.keys[id]
}

func (l *lab) delivered(t *testing.T, payload string) {
	t.Helper()
	l.data(l.c.cur.id, payload)
	select {
	case p := <-l.c.Packets:
		if string(p) != payload {
			t.Fatalf("got %q, want %q", p, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%q was not delivered", payload)
	}
}

// control packets that are not from this session's server change nothing:
// no new key, no other server session id, and lastIn does not move (so a
// dead server is still noticed)
func TestForgedControlPackets(t *testing.T) {
	l := newLab(t, 1)
	c := l.c
	var evil [8]byte
	copy(evil[:], "ATTACKER")
	cur := l.key(1)
	ks := cur
	<-ks.window
	ks.smu.Lock()
	ks.unacked[7] = &sentMsg{op: opControlV1, sent: time.Now()}
	ks.smu.Unlock()
	l.delivered(t, "before")

	old := time.Now().Add(-time.Hour).UnixNano()
	c.lastIn.Store(old)
	l.ctrl(opControlSoftResetV1, 1, evil, ctrlBody{hasMsg: true})
	l.ctrl(opControlSoftResetV1, 2, evil, ctrlBody{hasMsg: true})
	l.ctrl(opControlHardResetServerV2, 0, evil, ctrlBody{hasMsg: true})
	l.ctrl(opAckV1, 1, l.sid, ctrlBody{acks: []uint32{7}, remoteSID: evil}) // acks for another session
	l.tr.in <- []byte{opDataV2<<3 | 1, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	l.settle()
	if l.key(1) != cur || l.key(2) != nil || l.key(0) != nil {
		t.Error("a forged soft reset changed the keys")
	}
	c.mu.Lock()
	rsid := c.remoteSID
	c.mu.Unlock()
	if rsid != l.sid {
		t.Errorf("a forged hard reset set the server's session id to %q", rsid)
	}
	ks.smu.Lock()
	_, still := ks.unacked[7]
	ks.smu.Unlock()
	if !still {
		t.Error("an ack for another session was taken")
	}
	if c.lastIn.Load() != old {
		t.Error("forged packets moved lastIn")
	}
	l.delivered(t, "after")
	if c.lastIn.Load() == old {
		t.Error("a real data packet did not move lastIn")
	}

	// the server's own soft reset again (its ack was lost): acked again,
	// the key stays
	for len(l.tr.out) > 0 {
		<-l.tr.out
	}
	l.ctrl(opControlSoftResetV1, 1, l.sid, ctrlBody{hasMsg: true})
	l.settle()
	if l.key(1) != cur {
		t.Fatal("a repeated soft reset replaced the key in use")
	}
	acked := false
	for len(l.tr.out) > 0 {
		if p := <-l.tr.out; p[0] == opAckV1<<3|1 {
			acked = true
		}
	}
	if !acked {
		t.Error("the repeated soft reset was not acked")
	}
	l.delivered(t, "still")

	// a real new key: started once, a repeat leaves it alone
	l.ctrl(opControlSoftResetV1, 2, l.sid, ctrlBody{hasMsg: true})
	l.settle()
	k2 := l.key(2)
	if k2 == nil {
		t.Fatalf("the server's soft reset did not start key 2 (%v)", l.c.Err())
	}
	l.ctrl(opControlSoftResetV1, 2, l.sid, ctrlBody{hasMsg: true})
	l.settle()
	if l.key(2) != k2 {
		t.Error("a repeated soft reset restarted key 2")
	}
	if l.key(1) != cur {
		t.Error("starting key 2 dropped key 1")
	}
	l.ctrl(opControlSoftResetV1, 0, l.sid, ctrlBody{hasMsg: true})
	l.settle()
	if l.key(0) != nil {
		t.Error("key 0 is never renegotiated")
	}
}

// the send packet id never wraps around: the same AEAD nonce twice would
// give the traffic away
func TestPacketIDNeverWraps(t *testing.T) {
	l := newLab(t, 1)
	ks := l.key(1)
	ks.sendPID.Store(math.MaxUint32 - 1)
	ks.rekeyed.Store(true) // no renegotiation in this test
	if err := l.c.WritePacket([]byte("last")); err != nil {
		t.Fatal(err)
	}
	for len(l.tr.out) > 0 {
		<-l.tr.out
	}
	if err := l.c.WritePacket([]byte("wraps")); err == nil || !strings.Contains(err.Error(), "packet ids") {
		t.Fatalf("WritePacket after the last id: %v", err)
	}
	if len(l.tr.out) != 0 {
		t.Error("a packet went out with a used packet id")
	}
	select {
	case <-l.c.Done():
	case <-time.After(2 * time.Second):
		t.Error("the session did not end")
	}
}

// ---- against the fake server --------------------------------------------

// on renegotiation the client logs in with the auth-token (a one-time code
// is spent by then); a later PUSH_REPLY that renews the token keeps the
// session's options; the token is never in Pushed (so never logged)
func TestRenegotiationUsesAuthToken(t *testing.T) {
	p := newPKI(t)
	s := newFakeServer(t, p)
	s.push += ",auth-token SESS_TOKEN_1,auth-token-user ZTJlLXVzZXI="
	s.afterReneg = func(k *fsKey, tc *tls.Conn) {
		tc.Write([]byte("PUSH_REPLY,auth-token SESS_TOKEN_" + string('1'+k.id) + "\x00"))
	}
	c := s.connect(t, s.config(p), Login{User: "someone", Password: "123456"})
	if l := <-s.logins; l.pass != "123456" || l.user != "someone" {
		t.Fatalf("first login %+v", l)
	}
	if raw := strings.Join(c.Pushed().Raw, ","); strings.Contains(raw, "SESS_TOKEN") || strings.Contains(raw, "auth-token") {
		t.Errorf("the auth-token is in Pushed: %s", raw)
	}
	roundTrip(t, c, 0)
	for i, want := range []string{"SESS_TOKEN_1", "SESS_TOKEN_2"} {
		id := byte(i + 1)
		s.renegotiate(id)
		l := <-s.logins
		if l.key != id || l.user != "e2e-user" || l.pass != want {
			t.Errorf("renegotiation %d logged in with %+v, want the token %s", id, l, want)
		}
		waitKey(t, c, id)
		roundTrip(t, c, int(id))
		if p := c.Pushed(); p.Cipher != "AES-256-GCM" || !p.EKM || p.PeerID != 0 || !p.Address.IsValid() {
			t.Fatalf("a token renewal replaced the pushed options: %+v", p)
		}
	}
	if c.Err() != nil {
		t.Fatal(c.Err())
	}
}

// a retired or replaced key's control channel reader ends: renegotiations
// leak no goroutines, and Close leaves none
func TestRenegotiationLeaksNothing(t *testing.T) {
	p := newPKI(t)
	s := newFakeServer(t, p)
	cfg := s.config(p)
	c := s.connect(t, cfg, Login{User: "u", Password: "p"})
	for i := 1; i <= 10; i++ {
		id := byte((i-1)%7 + 1)
		s.renegotiate(id)
		waitKey(t, c, id)
		roundTrip(t, c, i)
	}
	for end := time.Now().Add(2 * time.Second); readers() > 2; {
		if time.Now().After(end) {
			t.Fatalf("%d control channel readers for one current and one old key", readers())
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Close()
	for end := time.Now().Add(3 * time.Second); readers() > 0; {
		if time.Now().After(end) {
			t.Fatalf("%d control channel readers left after Close", readers())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readers() int {
	b := make([]byte, 1<<20)
	return strings.Count(string(b[:runtime.Stack(b, true)]), "openvpn.(*Client).controlMessages(")
}

// long before the packet id could wrap, the client renegotiates by itself
func TestClientRenegotiates(t *testing.T) {
	p := newPKI(t)
	s := newFakeServer(t, p)
	c := s.connect(t, s.config(p), Login{User: "u", Password: "p"})
	<-s.logins
	c.mu.Lock()
	c.cur.sendPID.Store(rekeyPID - 1)
	c.mu.Unlock()
	roundTrip(t, c, 1)
	select {
	case id := <-s.softResets:
		if id != 1 {
			t.Errorf("the client renegotiated key %d, want 1", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not renegotiate")
	}
	waitKey(t, c, 1)
	roundTrip(t, c, 2)
	c.mu.Lock()
	pid := c.cur.sendPID.Load()
	c.mu.Unlock()
	if pid >= rekeyPID {
		t.Errorf("the new key starts at packet id %d", pid)
	}
}

// the client's own rekey never cuts off a renegotiation that already
// runs, such as the server's on the key id the client would pick: it
// waits, and tries again on a later packet
func TestClientRekeyWaitsForPending(t *testing.T) {
	c := &Client{}
	from := c.makeKey(0)
	from.pending = false
	server := c.makeKey(1) // the server's soft reset, still running
	c.keys[0], c.keys[1], c.cur = from, server, from
	c.rekey(from)
	if c.keys[1] != server {
		t.Fatal("the client's rekey replaced the server's pending key")
	}
	if from.rekeyed.Load() {
		t.Error("the rekey is marked done, so it is never tried again")
	}
}

// a server cannot make the client hold any amount of memory
func TestControlMessageLimits(t *testing.T) {
	for _, c := range []struct {
		name, want string
		flood      func(tc *tls.Conn)
	}{
		{"no NUL", "too long", func(tc *tls.Conn) {
			chunk := strings.Repeat("x", 4096)
			for i := 0; i < 40; i++ {
				if _, err := tc.Write([]byte(chunk)); err != nil {
					return
				}
			}
		}},
		{"endless continuation", "too many options", func(tc *tls.Conn) {
			opt := "PUSH_REPLY,route 10.0.0.0 255.0.0.0 " + strings.Repeat("y", 2000) + ",push-continuation 2\x00"
			for i := 0; i < 200; i++ {
				if _, err := tc.Write([]byte(opt)); err != nil {
					return
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPKI(t)
			s := newFakeServer(t, p)
			up := make(chan struct{})
			s.afterPush = func(_ *fsKey, tc *tls.Conn) { go func() { <-up; c.flood(tc) }() }
			cl := s.connect(t, s.config(p), Login{User: "u", Password: "p"})
			close(up)
			select {
			case <-cl.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("the session goes on")
			}
			if err := cl.Err(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want %q", err, c.want)
			}
		})
	}
}
