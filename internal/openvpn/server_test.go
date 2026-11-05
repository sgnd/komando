package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeServer is a small OpenVPN server on loopback TCP for the tests: a
// plain control channel, TLS and key-method 2 on every key, one push, and
// a data channel that echoes what the client sends.
type fakeServer struct {
	t      *testing.T
	ln     net.Listener
	tlsCfg *tls.Config
	push   string // the PUSH_REPLY, without the NUL

	// hooks on the server's TLS stream of a key: after the first push
	// (key 0), and after a renegotiation's key exchange
	afterPush  func(k *fsKey, tc *tls.Conn)
	afterReneg func(k *fsKey, tc *tls.Conn)

	logins     chan fsLogin
	softResets chan byte // keys the client renegotiated by itself

	wmu  sync.Mutex
	conn net.Conn
	sid  [8]byte

	mu   sync.Mutex
	csid [8]byte
	keys map[byte]*fsKey
}

type fsLogin struct {
	key        byte
	user, pass string
}

type fsKey struct {
	id byte
	s  *fakeServer

	smu  sync.Mutex
	next uint32

	rmu    sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	expect uint32
	closed bool

	// under s.mu
	data dataCipher
	pid  uint32
}

func newFakeServer(t *testing.T, p *testPKI) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, ln: ln, keys: map[byte]*fsKey{}, logins: make(chan fsLogin, 64), softResets: make(chan byte, 8),
		tlsCfg: &tls.Config{Certificates: []tls.Certificate{p.server()}, MinVersion: tls.VersionTLS12},
		push:   "PUSH_REPLY,cipher AES-256-GCM,key-derivation tls-ekm,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,ping 10,ping-restart 120"}
	copy(s.sid[:], "fakesrv!")
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s.wmu.Lock()
		s.conn = c
		s.wmu.Unlock()
		s.readLoop(c)
	}()
	t.Cleanup(s.close)
	return s
}

func (s *fakeServer) close() {
	s.ln.Close()
	s.wmu.Lock()
	if s.conn != nil {
		s.conn.Close()
	}
	s.wmu.Unlock()
	s.mu.Lock()
	for _, k := range s.keys {
		k.end()
	}
	s.mu.Unlock()
}

// config is a client profile for this server.
func (s *fakeServer) config(p *testPKI) *Config {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	return &Config{Remotes: []Remote{{"127.0.0.1", port, "tcp"}}, CA: p.caPEM, KeyDirection: -1, Ciphers: []string{"AES-256-GCM"},
		Auth: "SHA1", AuthUserPass: true, Setenv: map[string]string{}, TunMTU: 1500}
}

func (s *fakeServer) connect(t *testing.T, cfg *Config, login Login) *Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := Connect(ctx, cfg, login, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// key is key id's state; fresh replaces an older one with that id.
func (s *fakeServer) key(id byte, fresh bool) (*fsKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.keys[id]
	if k != nil && !fresh {
		return k, false
	}
	if k != nil {
		k.end()
	}
	k = &fsKey{id: id, s: s}
	k.cond = sync.NewCond(&k.rmu)
	s.keys[id] = k
	return k, true
}

// raw sends a packet as it is.
func (s *fakeServer) raw(pkt []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	b := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(b, uint16(len(pkt)))
	copy(b[2:], pkt)
	s.conn.Write(b)
}

func (k *fsKey) send(op byte, payload []byte) {
	k.smu.Lock()
	id := k.next
	k.next++
	k.smu.Unlock()
	k.s.mu.Lock()
	csid := k.s.csid
	k.s.mu.Unlock()
	k.s.raw(plainWrap{}.wrap(op<<3|k.id, k.s.sid, encodeBody(ctrlBody{remoteSID: csid, msgID: id, payload: payload, hasMsg: true})))
}

func (k *fsKey) recv(op byte, b ctrlBody) {
	if !b.hasMsg {
		return
	}
	k.s.mu.Lock()
	csid := k.s.csid
	k.s.mu.Unlock()
	k.s.raw(plainWrap{}.wrap(opAckV1<<3|k.id, k.s.sid, encodeBody(ctrlBody{acks: []uint32{b.msgID}, remoteSID: csid})))
	k.rmu.Lock()
	if b.msgID == k.expect {
		k.expect++
		if op == opControlV1 {
			k.buf.Write(b.payload)
			k.cond.Broadcast()
		}
	}
	k.rmu.Unlock()
}

func (k *fsKey) end() {
	k.rmu.Lock()
	k.closed = true
	k.cond.Broadcast()
	k.rmu.Unlock()
}

// fsKey is the net.Conn the server's TLS for this key runs on
func (k *fsKey) Read(b []byte) (int, error) {
	k.rmu.Lock()
	defer k.rmu.Unlock()
	for k.buf.Len() == 0 {
		if k.closed {
			return 0, io.EOF
		}
		k.cond.Wait()
	}
	return k.buf.Read(b)
}

func (k *fsKey) Write(b []byte) (int, error) {
	for off := 0; off < len(b); off += maxCtrlPayload {
		k.send(opControlV1, b[off:min(off+maxCtrlPayload, len(b))])
	}
	return len(b), nil
}
func (k *fsKey) Close() error                     { k.end(); return nil }
func (k *fsKey) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (k *fsKey) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (k *fsKey) SetDeadline(time.Time) error      { return nil }
func (k *fsKey) SetReadDeadline(time.Time) error  { return nil }
func (k *fsKey) SetWriteDeadline(time.Time) error { return nil }

func (s *fakeServer) readLoop(c net.Conn) {
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		pkt := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		op, kid := pkt[0]>>3, pkt[0]&7
		if op == opDataV1 || op == opDataV2 {
			s.echo(op, kid, pkt)
			continue
		}
		_, sid, body, err := plainWrap{}.unwrap(pkt)
		if err != nil {
			continue
		}
		b, err := decodeBody(pkt[0], body)
		if err != nil {
			continue
		}
		switch op {
		case opControlHardResetClientV2:
			s.mu.Lock()
			s.csid = sid
			s.mu.Unlock()
			k, isNew := s.key(0, false)
			k.recv(op, b)
			if isNew {
				k.send(opControlHardResetServerV2, nil)
				go s.session(k, true)
			}
		case opControlSoftResetV1:
			k, isNew := s.key(kid, false)
			if isNew {
				select {
				case s.softResets <- kid:
				default:
				}
				k.recv(op, b)
				k.send(opControlSoftResetV1, nil)
				go s.session(k, false)
			} else {
				k.recv(op, b)
			}
		case opControlV1:
			k, _ := s.key(kid, false)
			k.recv(op, b)
		}
	}
}

// renegotiate starts key id from the server's side.
func (s *fakeServer) renegotiate(id byte) {
	k, _ := s.key(id, true)
	k.send(opControlSoftResetV1, nil)
	go s.session(k, false)
}

func (s *fakeServer) session(k *fsKey, first bool) {
	tc := tls.Server(k, s.tlsCfg)
	if err := tc.Handshake(); err != nil {
		return
	}
	head := make([]byte, 5+48+64)
	if _, err := io.ReadFull(tc, head); err != nil {
		return
	}
	readString(tc) // options
	user, _ := readString(tc)
	pass, _ := readString(tc)
	readString(tc) // peer info
	select {
	case s.logins <- fsLogin{k.id, user, pass}:
	default:
	}
	var msg bytes.Buffer
	msg.Write([]byte{0, 0, 0, 0, 2})
	rnd := make([]byte, 64)
	rand.Read(rnd)
	msg.Write(rnd)
	writeString(&msg, "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth SHA1,keysize 256,key-method 2,tls-server")
	tc.Write(msg.Bytes())
	st := tc.ConnectionState()
	material, _ := st.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
	ssend, srecv := keyPair(material, 1)
	dc, _ := newAEAD("AES-256-GCM", ssend, srecv)
	s.mu.Lock()
	k.data = dc
	s.mu.Unlock()
	if first {
		var in []byte
		tmp := make([]byte, 4096)
		for !bytes.Contains(in, []byte("PUSH_REQUEST\x00")) {
			n, err := tc.Read(tmp)
			if err != nil {
				return
			}
			in = append(in, tmp[:n]...)
		}
		tc.Write([]byte(s.push + "\x00"))
		if s.afterPush != nil {
			s.afterPush(k, tc)
		}
	} else if s.afterReneg != nil {
		s.afterReneg(k, tc)
	}
	io.Copy(io.Discard, tc)
}

// echo sends a data packet back on the key it came on.
func (s *fakeServer) echo(op, kid byte, pkt []byte) {
	if op != opDataV2 || len(pkt) < 4 {
		return
	}
	s.mu.Lock()
	k := s.keys[kid]
	if k == nil || k.data == nil {
		s.mu.Unlock()
		return
	}
	dc := k.data
	k.pid++
	pid := k.pid
	s.mu.Unlock()
	ad := pkt[:4]
	_, plain, err := dc.open(ad, pkt[4:])
	if err != nil {
		return
	}
	s.raw(append(append([]byte{}, ad...), dc.seal(pid, ad, plain)...))
}

// curKey is the client's data key id.
func curKey(c *Client) byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur.id
}

// waitKey waits until the client sends data on key id.
func waitKey(t *testing.T, c *Client, id byte) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); curKey(c) != id; {
		if time.Now().After(end) {
			t.Fatalf("the client is on key %d, not %d (err %v)", curKey(c), id, c.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// roundTrip sends one packet through the tunnel and waits for its echo.
func roundTrip(t *testing.T, c *Client, n int) {
	t.Helper()
	want := "\x45packet " + strconv.Itoa(n)
	if err := c.WritePacket([]byte(want)); err != nil {
		t.Fatal(err)
	}
	// a tunnel may drop a packet, as IP may: right after a renegotiation the
	// fake server can get the client's first packet on the new key before it
	// has installed that key, so the packet is sent again until it comes back
	resend := time.NewTicker(500 * time.Millisecond)
	defer resend.Stop()
	for end := time.After(10 * time.Second); ; {
		select {
		case p := <-c.Packets:
			if string(p) == want {
				return
			}
		case <-resend.C:
			if err := c.WritePacket([]byte(want)); err != nil {
				t.Fatal(err)
			}
		case <-end:
			t.Fatalf("packet %d did not come back (key %d, err %v)", n, curKey(c), c.Err())
		}
	}
}
