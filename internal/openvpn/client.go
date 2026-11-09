package openvpn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// debugf writes protocol events to stderr when KOMANDO_OVPN_DEBUG is set
// (the session's server writes stderr to its log file). Never secrets.
func debugf(format string, a ...any) {
	if os.Getenv("KOMANDO_OVPN_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "openvpn: "+format+"\n", a...)
	}
}

// Login is the user name and password for auth-user-pass (Pritunl puts a
// PIN or one-time code into the password the way its client does).
type Login struct{ User, Password string }

// Pushed is what the server pushed.
type Pushed struct {
	Address     netip.Prefix // ifconfig
	Address6    netip.Prefix
	DNS         []netip.Addr
	Cipher      string
	PeerID      int // -1 when none
	Ping        time.Duration
	PingRestart time.Duration
	EKM         bool
	MTU         int
	Raw         []string
}

// Client is one connected OpenVPN session.
type Client struct {
	cfg      *Config
	login    Login
	tr       transport
	wrap     ctrlWrap
	localSID [8]byte

	mu        sync.Mutex
	remoteSID [8]byte
	remoteSet bool // remoteSID is the server's, from its hard reset
	keys      [8]*keyState
	cur       *keyState
	old       *keyState
	oldTill   time.Time
	pushed    Pushed
	// token is the auth-token the server pushed: on renegotiation it is
	// sent in place of the password (a one-time code is spent by then).
	// It is never logged and never in Pushed.
	token, tokenUser string

	// Packets is where decrypted IP packets arrive.
	Packets chan []byte
	done    chan struct{}
	err     atomic.Value
	lastIn  atomic.Int64
	once    sync.Once
}

type keyState struct {
	id byte
	c  *Client

	smu     sync.Mutex
	nextID  uint32
	unacked map[uint32]*sentMsg
	window  chan struct{} // free send slots

	rmu     sync.Mutex
	expect  uint32
	ooo     map[uint32][]byte
	acks    []uint32
	inbuf   bytes.Buffer
	incond  *sync.Cond
	inclose bool

	// under Client.mu
	data    dataCipher
	pending bool // its handshake still runs

	sendPID atomic.Uint32
	rekeyed atomic.Bool // a renegotiation away from this key was started
	rp      replay
	rpmu    sync.Mutex
}

type sentMsg struct {
	op      byte
	payload []byte
	sent    time.Time
	tries   int
}

const (
	maxCtrlPayload = 1000
	// maxCtrlMsg bounds one NUL-ended control message and maxPush a
	// pushed reply with its continuations, so a server cannot make the
	// client hold any amount of memory
	maxCtrlMsg = 64 << 10
	maxPush    = 256 << 10
	// rekeyPID is the send packet id from which the client renegotiates
	// by itself (OpenVPN does the same): an AEAD packet id must never
	// repeat under one key, and the server may never renegotiate
	rekeyPID = 0xFF000000
)

// Connect dials the first remote that answers and completes the handshake.
func Connect(ctx context.Context, cfg *Config, login Login, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*Client, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second}).DialContext
	}
	var lastErr error
	for _, r := range cfg.Remotes {
		c, err := connectOne(ctx, cfg, login, r, dial)
		if err == nil {
			return c, nil
		}
		lastErr = fmt.Errorf("%s:%s (%s): %w", r.Host, r.Port, r.Proto, err)
		var ae *AuthError
		if errors.As(err, &ae) || ctx.Err() != nil {
			return nil, lastErr // a refused login is the same on every remote
		}
	}
	return nil, lastErr
}

// AuthError is a login the server refused.
type AuthError struct{ Msg string }

func (e *AuthError) Error() string { return "the server refused the login: " + e.Msg }

func connectOne(ctx context.Context, cfg *Config, login Login, r Remote, dial func(context.Context, string, string) (net.Conn, error)) (*Client, error) {
	nc, err := dial(ctx, r.Proto, net.JoinHostPort(r.Host, r.Port))
	if err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, login: login, Packets: make(chan []byte, 256), done: make(chan struct{})}
	if r.Proto == "tcp" {
		c.tr = &tcpTransport{c: nc}
	} else {
		c.tr = &udpTransport{c: nc}
	}
	switch {
	case cfg.TLSCrypt != nil:
		c.wrap = newCryptWrap(cfg.TLSCrypt)
	case cfg.TLSAuth != nil:
		w, err := newAuthWrap(cfg.TLSAuth, cfg.KeyDirection, cfg.Auth)
		if err != nil {
			nc.Close()
			return nil, err
		}
		c.wrap = w
	default:
		c.wrap = plainWrap{}
	}
	rand.Read(c.localSID[:])
	c.lastIn.Store(time.Now().UnixNano())
	ks := c.newKey(0)
	c.cur = ks
	go c.readLoop()
	go c.retransmitLoop()
	hctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := c.handshake(hctx, ks, true); err != nil {
		c.Close()
		return nil, err
	}
	go c.keepalive()
	debugf("connected to %s:%s (%s), pushed %v", r.Host, r.Port, r.Proto, c.Pushed().Raw) // Raw holds no auth-token
	return c, nil
}

// newKey starts key id; a key that held the slot before is closed.
func (c *Client) newKey(id byte) *keyState {
	ks := c.makeKey(id)
	c.mu.Lock()
	prev := c.keys[id]
	c.keys[id] = ks
	c.mu.Unlock()
	if prev != nil {
		prev.closeIn()
	}
	return ks
}

// makeKey is a new key id, not yet in its slot.
func (c *Client) makeKey(id byte) *keyState {
	ks := &keyState{id: id, c: c, unacked: map[uint32]*sentMsg{}, ooo: map[uint32][]byte{}, window: make(chan struct{}, 4), pending: true}
	for i := 0; i < cap(ks.window); i++ {
		ks.window <- struct{}{}
	}
	ks.incond = sync.NewCond(&ks.rmu)
	return ks
}

// retire drops a key that is no longer used (c.mu held): its slot, unless
// a newer key took it, and its control channel reader.
func (c *Client) retire(ks *keyState) {
	if c.keys[ks.id] == ks {
		c.keys[ks.id] = nil
	}
	ks.closeIn()
}

// closeIn ends the key's TLS stream, so whatever reads it returns.
func (ks *keyState) closeIn() {
	ks.rmu.Lock()
	ks.inclose = true
	ks.incond.Broadcast()
	ks.rmu.Unlock()
}

// handshake runs TLS and the key exchange on ks. first is the initial
// session (hard reset, then PUSH_REQUEST); otherwise a renegotiation.
func (c *Client) handshake(ctx context.Context, ks *keyState, first bool) error {
	if first {
		if err := ks.sendMsg(opControlHardResetClientV2, nil); err != nil {
			return err
		}
		// wait for the server's reset (it sets remoteSID)
		if err := waitFor(ctx, c.done, func() bool {
			ks.rmu.Lock()
			defer ks.rmu.Unlock()
			return ks.expect > 0
		}); err != nil {
			return c.failure(fmt.Errorf("no answer from the server: %w", err))
		}
	}
	tc, err := c.tlsConfig()
	if err != nil {
		return err
	}
	conn := tls.Client(&ctrlConn{ks: ks}, tc)
	if err := conn.HandshakeContext(ctx); err != nil {
		return c.failure(fmt.Errorf("TLS: %w", err))
	}
	// key method 2
	var pre [48]byte
	var r1, r2 [32]byte
	rand.Read(pre[:])
	rand.Read(r1[:])
	rand.Read(r2[:])
	var msg bytes.Buffer
	msg.Write([]byte{0, 0, 0, 0, 2})
	msg.Write(pre[:])
	msg.Write(r1[:])
	msg.Write(r2[:])
	writeString(&msg, c.optionsString())
	if c.cfg.AuthUserPass {
		user, pass := c.login.User, c.login.Password
		c.mu.Lock()
		if !first && c.token != "" {
			pass = c.token
			if c.tokenUser != "" {
				user = c.tokenUser
			}
		}
		c.mu.Unlock()
		writeString(&msg, user)
		writeString(&msg, pass)
	} else {
		msg.Write([]byte{0, 0, 0, 0})
	}
	writeString(&msg, c.peerInfo())
	if _, err := conn.Write(msg.Bytes()); err != nil {
		return c.failure(err)
	}
	// the server's half: 0000, method, random1, random2, options
	head := make([]byte, 5+64)
	if err := readFull(ctx, conn, head); err != nil {
		return c.failure(fmt.Errorf("key exchange: %w", err))
	}
	if !bytes.Equal(head[:4], []byte{0, 0, 0, 0}) || head[4] != 2 {
		return c.failure(errors.New("the server does not speak key-method 2"))
	}
	sr1, sr2 := head[5:37], head[37:69]
	if _, err := readString(conn); err != nil { // the server's options
		return c.failure(fmt.Errorf("key exchange: %w", err))
	}
	derive := func(ekm bool) ([]byte, error) {
		if ekm {
			st := conn.ConnectionState()
			return st.ExportKeyingMaterial("EXPORTER-OpenVPN-datakeys", nil, 256)
		}
		master := prf(pre[:], "OpenVPN master secret", append(append([]byte{}, r1[:]...), sr1...), 48)
		c.mu.Lock()
		rsid := c.remoteSID
		c.mu.Unlock()
		seed := append(append(append(append([]byte{}, r2[:]...), sr2...), c.localSID[:]...), rsid[:]...)
		return prf(master, "OpenVPN key expansion", seed, 256), nil
	}
	go c.controlMessages(conn)
	if first {
		if err := c.pull(ctx, conn); err != nil {
			return err
		}
	}
	c.mu.Lock()
	p := c.pushed
	c.mu.Unlock()
	material, err := derive(p.EKM)
	if err != nil {
		return c.failure(err)
	}
	dc, err := newDataCipher(p.Cipher, c.cfg.Auth, material)
	if err != nil {
		return c.failure(err)
	}
	ks.sendPID.Store(0)
	c.mu.Lock()
	ks.data, ks.pending = dc, false
	if !first {
		if c.old != nil && c.old != ks {
			c.retire(c.old)
		}
		c.old, c.oldTill = c.cur, time.Now().Add(60*time.Second)
	}
	c.cur = ks
	c.mu.Unlock()
	return nil
}

func (c *Client) failure(err error) error {
	if e, ok := c.err.Load().(error); ok && e != nil {
		return e // the server said why (AUTH_FAILED)
	}
	return err
}

func (c *Client) tlsConfig() (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.cfg.CA) {
		return nil, errors.New("the <ca> block holds no certificate")
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// OpenVPN checks the CA chain, not a host name: done below
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("the server sent no certificate")
			}
			certs := make([]*x509.Certificate, len(raw))
			for i, r := range raw {
				crt, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs[i] = crt
			}
			inter := x509.NewCertPool()
			for _, x := range certs[1:] {
				inter.AddCert(x)
			}
			opts := x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
			if c.cfg.RemoteCertTLS {
				opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			if _, err := certs[0].Verify(opts); err != nil {
				return fmt.Errorf("the server's certificate: %w", err)
			}
			if err := c.cfg.checkUsage(certs[0]); err != nil {
				return err
			}
			if n := c.cfg.VerifyName; n != "" {
				cn := certs[0].Subject.CommonName
				switch c.cfg.VerifyNameType {
				case "name":
					if cn != n {
						return fmt.Errorf("the server's certificate is for %q, not %q (verify-x509-name)", cn, n)
					}
				case "name-prefix":
					if !strings.HasPrefix(cn, n) {
						return fmt.Errorf("the server's certificate is for %q, not %q... (verify-x509-name)", cn, n)
					}
				default: // the whole subject, as OpenVPN prints it
					dn := subjectDN(certs[0])
					if !matchSubject(certs[0], n) && certs[0].Subject.String() != n {
						return fmt.Errorf("the server's certificate is for %q, not %q (verify-x509-name)", dn, n)
					}
				}
			}
			return nil
		},
	}
	if c.cfg.TLSMin == "1.3" {
		tc.MinVersion = tls.VersionTLS13
	}
	if c.cfg.Cert != nil {
		pair, err := tls.X509KeyPair(c.cfg.Cert, c.cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return tc, nil
}

func (c *Client) optionsString() string {
	return "V4,dev-type tun,link-mtu 1549,tun-mtu " + strconv.Itoa(c.cfg.TunMTU) + ",proto " +
		map[bool]string{true: "TCPv4_CLIENT", false: "UDPv4"}[c.isTCP()] + ",cipher " + c.cfg.Ciphers[0] + ",auth " + c.cfg.Auth +
		",keysize 256,key-method 2,tls-client"
}

func (c *Client) isTCP() bool { _, ok := c.tr.(*tcpTransport); return ok }

func (c *Client) peerInfo() string {
	plat := map[string]string{"darwin": "mac", "windows": "win"}[runtime.GOOS]
	if plat == "" {
		plat = runtime.GOOS
	}
	// IV_PROTO: 2 data v2 (peer id), 4 request push, 8 TLS key export.
	// KOMANDO_OVPN_NO_EKM leaves out 8, so tests reach the PRF of servers
	// before 2.6.
	proto := "14"
	if os.Getenv("KOMANDO_OVPN_NO_EKM") != "" {
		proto = "6"
	}
	var b strings.Builder
	b.WriteString("IV_VER=2.6.12\nIV_PLAT=" + plat + "\nIV_PROTO=" + proto + "\nIV_NCP=2\nIV_CIPHERS=" + strings.Join(c.cfg.Ciphers, ":") +
		"\nIV_MTU=1600\nIV_TCPNL=1\nIV_GUI_VER=komando\n")
	for k, v := range c.cfg.Setenv {
		b.WriteString(k + "=" + v + "\n")
	}
	return b.String()
}

// pull asks for the pushed options until they come.
func (c *Client) pull(ctx context.Context, conn *tls.Conn) error {
	got := func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.pushed.Cipher != ""
	}
	for i := 0; ; i++ {
		if _, err := conn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
			return c.failure(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := waitFor(wctx, c.done, got)
		cancel()
		if err == nil {
			return nil
		}
		if e := c.failure(nil); e != nil {
			return e
		}
		if ctx.Err() != nil {
			return errors.New("the server pushed no options (PUSH_REPLY)")
		}
	}
}

// controlMessages reads the NUL-ended messages the server sends over TLS.
func (c *Client) controlMessages(conn *tls.Conn) {
	var buf []byte
	tmp := make([]byte, 4096)
	var reply []string
	size := 0
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			return
		}
		from := len(buf) // what came before holds no NUL
		buf = append(buf, tmp[:n]...)
		for {
			i := bytes.IndexByte(buf[from:], 0)
			if i < 0 {
				break
			}
			i += from
			m := string(buf[:i])
			buf, from = buf[i+1:], 0
			switch {
			case strings.HasPrefix(m, "PUSH_REPLY,"):
				if size += len(m); size > maxPush {
					c.end(errors.New("the server pushed too many options"))
					return
				}
				opts := strings.Split(strings.TrimPrefix(m, "PUSH_REPLY,"), ",")
				reply = append(reply, opts...)
				more := false
				for _, o := range opts {
					if strings.TrimSpace(o) == "push-continuation 2" {
						more = true
					}
				}
				if !more {
					c.takePush(reply)
					reply, size = nil, 0
				}
			case strings.HasPrefix(m, "AUTH_FAILED"):
				c.fail(&AuthError{Msg: strings.TrimPrefix(strings.TrimPrefix(m, "AUTH_FAILED"), ",")})
			case strings.HasPrefix(m, "RESTART"), strings.HasPrefix(m, "HALT"):
				c.fail(fmt.Errorf("the server ended the session: %s", m))
			}
		}
		if len(buf) > maxCtrlMsg {
			c.end(errors.New("the server sent a control message that is too long"))
			return
		}
	}
}

// takePush keeps a PUSH_REPLY. The first one sets up the session; a later
// one (OpenVPN renews the auth-token that way) only updates the token, as
// the data keys depend on what the first one said.
func (c *Client) takePush(opts []string) {
	var keep []string
	tok, tokUser := "", ""
	for _, o := range opts {
		f := strings.Fields(o)
		switch {
		case len(f) > 0 && f[0] == "auth-token":
			if len(f) > 1 {
				tok = f[1]
			}
		case len(f) > 0 && f[0] == "auth-token-user":
			if len(f) > 1 {
				if u, err := base64.StdEncoding.DecodeString(f[1]); err == nil {
					tokUser = string(u)
				}
			}
		default:
			keep = append(keep, o)
		}
	}
	c.mu.Lock()
	if tok != "" {
		c.token = tok
	}
	if tokUser != "" {
		c.tokenUser = tokUser
	}
	initial := c.pushed.Cipher == ""
	c.mu.Unlock()
	if !initial {
		return
	}
	p := c.parsePush(keep)
	c.mu.Lock()
	if c.pushed.Cipher == "" {
		c.pushed = p
	}
	c.mu.Unlock()
}

func (c *Client) parsePush(opts []string) Pushed {
	p := Pushed{PeerID: -1, Ping: 10 * time.Second, PingRestart: 120 * time.Second, MTU: c.cfg.TunMTU, Raw: opts}
	for _, o := range opts {
		f := strings.Fields(o)
		if len(f) == 0 {
			continue
		}
		arg := func(i int) string {
			if i < len(f) {
				return f[i]
			}
			return ""
		}
		switch f[0] {
		case "ifconfig":
			ip, err1 := netip.ParseAddr(arg(1))
			mask := net.ParseIP(arg(2))
			bits := 32
			if err1 == nil && mask != nil && mask.To4() != nil {
				ones, _ := net.IPMask(mask.To4()).Size()
				if ones > 0 {
					bits = ones
				}
			}
			if err1 == nil {
				p.Address = netip.PrefixFrom(ip, bits)
			}
		case "ifconfig-ipv6":
			if pf, err := netip.ParsePrefix(arg(1)); err == nil {
				p.Address6 = pf
			}
		case "dhcp-option":
			if strings.EqualFold(arg(1), "DNS") || strings.EqualFold(arg(1), "DNS6") {
				if a, err := netip.ParseAddr(arg(2)); err == nil {
					p.DNS = append(p.DNS, a)
				}
			}
		case "dns":
			if arg(1) == "server" && arg(3) == "address" {
				if a, err := netip.ParseAddr(arg(4)); err == nil {
					p.DNS = append(p.DNS, a)
				}
			}
		case "cipher":
			p.Cipher = strings.ToUpper(arg(1))
		case "peer-id":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				p.PeerID = n
			}
		case "ping":
			if n, err := strconv.Atoi(arg(1)); err == nil && n > 0 {
				p.Ping = time.Duration(n) * time.Second
			}
		case "ping-restart":
			if n, err := strconv.Atoi(arg(1)); err == nil && n > 0 {
				p.PingRestart = time.Duration(n) * time.Second
			}
		case "key-derivation":
			p.EKM = arg(1) == "tls-ekm"
		case "tun-mtu":
			if n, err := strconv.Atoi(arg(1)); err == nil {
				p.MTU = n
			}
		}
	}
	if p.Cipher == "" {
		p.Cipher = c.cfg.Ciphers[0]
	}
	if !supportedCipher(p.Cipher) {
		c.fail(fmt.Errorf("the server chose cipher %s, which komando does not support", p.Cipher))
	}
	return p
}

// Pushed are the options the server pushed.
func (c *Client) Pushed() Pushed {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pushed
}

func (c *Client) fail(err error) {
	c.err.CompareAndSwap(nil, err)
	if _, ok := err.(*AuthError); ok {
		c.Close()
	}
}

// end ends the session for err.
func (c *Client) end(err error) {
	c.fail(err)
	c.Close()
}

// Err is why the session ended, if it did.
func (c *Client) Err() error {
	if e, ok := c.err.Load().(error); ok {
		return e
	}
	return nil
}

// Done is closed when the session ends.
func (c *Client) Done() <-chan struct{} { return c.done }

// Close ends the session.
func (c *Client) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.tr.Close()
		c.mu.Lock()
		for _, ks := range c.keys {
			if ks != nil {
				ks.closeIn()
			}
		}
		if c.old != nil {
			c.old.closeIn()
		}
		c.mu.Unlock()
	})
	return nil
}

// Reading packets.

func (c *Client) readLoop() {
	for {
		pkt, err := c.tr.Read()
		if err != nil {
			select {
			case <-c.done:
			default:
				c.fail(fmt.Errorf("connection to the server lost: %w", err))
				c.Close()
			}
			return
		}
		if len(pkt) < 1 {
			continue
		}
		// lastIn moves only for packets that check out (onControl,
		// onData), so forged ones cannot hide a dead server
		op, kid := pkt[0]>>3, pkt[0]&7
		switch op {
		case opDataV1, opDataV2:
			c.onData(op, kid, pkt)
		default:
			c.onControl(op, kid, pkt)
		}
	}
}

func (c *Client) onControl(op, kid byte, pkt []byte) {
	_, sid, body, err := c.wrap.unwrap(pkt)
	if err != nil {
		return // a forged or broken packet: ignore it
	}
	b, err := decodeBody(pkt[0], body)
	if err != nil {
		return
	}
	if len(b.acks) > 0 && b.remoteSID != c.localSID {
		return // acks for another session
	}
	c.mu.Lock()
	switch {
	case !c.remoteSet:
		// nothing comes before the server's hard reset on key 0 but an
		// ack of the client's (it names this session, checked above)
		if kid != 0 || op != opControlHardResetServerV2 && (op != opAckV1 || len(b.acks) == 0) {
			c.mu.Unlock()
			return
		}
		if op == opControlHardResetServerV2 {
			c.remoteSID, c.remoteSet = sid, true
		}
	case sid != c.remoteSID:
		c.mu.Unlock()
		return // not this session's server
	case op == opControlHardResetServerV2 && kid != 0:
		c.mu.Unlock()
		return
	}
	ks := c.keys[kid]
	// a soft reset starts a new key only for a key id not in use; the same
	// packet again (a lost ack) is only acked again
	start := op == opControlSoftResetV1 && kid != 0 && b.hasMsg && b.msgID == 0 &&
		(ks == nil || ks != c.cur && ks != c.old && !ks.pending)
	c.mu.Unlock()
	c.lastIn.Store(time.Now().UnixNano())
	if start {
		ks = c.newKey(kid) // the server starts a new key
		go c.renegotiate(ks)
	}
	if ks == nil {
		return
	}
	ks.onAcks(b.acks)
	if b.hasMsg {
		ks.onMsg(b.msgID, b.payload, op == opControlV1)
	}
}

// renegotiate runs the handshake of a new key. When it fails the session
// ends, so it is reported down instead of carrying on with a key the
// server is about to drop.
func (c *Client) renegotiate(ks *keyState) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.handshake(ctx, ks, false); err != nil {
		select {
		case <-c.done: // closed meanwhile: that is the reason
		default:
			c.end(fmt.Errorf("renegotiation: %w", err))
		}
	}
}

// rekey starts a renegotiation from the client's side, once per key.
func (c *Client) rekey(from *keyState) {
	if !from.rekeyed.CompareAndSwap(false, true) {
		return
	}
	next := from.id%7 + 1 // key id 0 is only the first key
	ks := c.makeKey(next)
	c.mu.Lock()
	for _, k := range c.keys {
		if k != nil && k.pending {
			// a renegotiation already runs, most likely the server's on
			// this same key id: let it finish instead of cutting it off,
			// and try again on the next packet if it does not move us on
			c.mu.Unlock()
			from.rekeyed.Store(false)
			return
		}
	}
	if c.old != nil && c.old.id == next {
		c.retire(c.old)
		c.old = nil
	}
	prev := c.keys[next]
	c.keys[next] = ks
	c.mu.Unlock()
	if prev != nil {
		prev.closeIn()
	}
	debugf("renegotiating: key %d to key %d", from.id, next)
	go func() {
		if err := ks.sendMsg(opControlSoftResetV1, nil); err != nil {
			c.end(fmt.Errorf("renegotiation: %w", err))
			return
		}
		c.renegotiate(ks)
	}()
}

func (ks *keyState) onAcks(acks []uint32) {
	if len(acks) == 0 {
		return
	}
	ks.smu.Lock()
	for _, a := range acks {
		if _, ok := ks.unacked[a]; ok {
			delete(ks.unacked, a)
			ks.window <- struct{}{}
		}
	}
	ks.smu.Unlock()
}

func (ks *keyState) onMsg(id uint32, payload []byte, tlsData bool) {
	ks.rmu.Lock()
	ks.acks = append(ks.acks, id)
	switch {
	case id == ks.expect:
		ks.expect++
		if tlsData {
			ks.inbuf.Write(payload)
		}
		for {
			p, ok := ks.ooo[ks.expect]
			if !ok {
				break
			}
			delete(ks.ooo, ks.expect)
			ks.inbuf.Write(p)
			ks.expect++
		}
		ks.incond.Broadcast()
	case id > ks.expect && id < ks.expect+64 && tlsData:
		ks.ooo[id] = append([]byte{}, payload...)
	}
	ks.rmu.Unlock()
	ks.flushAcks()
}

// flushAcks sends the pending acks in their own packet.
func (ks *keyState) flushAcks() {
	ks.rmu.Lock()
	acks := ks.acks
	if len(acks) > 8 {
		acks = acks[:8]
	}
	ks.acks = ks.acks[len(acks):]
	ks.rmu.Unlock()
	if len(acks) == 0 {
		return
	}
	c := ks.c
	c.mu.Lock()
	rsid := c.remoteSID
	c.mu.Unlock()
	body := encodeBody(ctrlBody{acks: acks, remoteSID: rsid})
	c.tr.Write(c.wrap.wrap(opAckV1<<3|ks.id, c.localSID, body))
}

func (c *Client) onData(op, kid byte, pkt []byte) {
	c.mu.Lock()
	ks := c.keys[kid]
	var dc dataCipher
	if ks != nil && (ks == c.cur || ks == c.old && time.Now().Before(c.oldTill)) {
		dc = ks.data
	}
	c.mu.Unlock()
	if dc == nil {
		return
	}
	var ad, body []byte
	if op == opDataV2 {
		if len(pkt) < 4 {
			return
		}
		ad, body = pkt[:4], pkt[4:]
	} else {
		body = pkt[1:]
	}
	pid, plain, err := dc.open(ad, body)
	if err != nil {
		debugf("data packet (op %d key %d, %d bytes) does not open: %v", op, kid, len(pkt), err)
		return
	}
	ks.rpmu.Lock()
	fresh := ks.rp.ok(pid)
	ks.rpmu.Unlock()
	if !fresh {
		return
	}
	c.lastIn.Store(time.Now().UnixNano())
	plain = c.uncompress(plain)
	if plain == nil || bytes.Equal(plain, pingString) {
		return
	}
	debugf("data in: %d bytes, pid %d", len(plain), pid)
	select {
	case c.Packets <- plain:
	default: // the stack is behind: drop, as a router would
	}
}

func (c *Client) uncompress(p []byte) []byte {
	switch c.cfg.Compress {
	case "lzo-no":
		if len(p) == 0 || p[0] != 0xFA {
			return nil
		}
		return p[1:]
	case "stub-v2":
		if len(p) >= 2 && p[0] == 0x50 {
			if p[1] != 0 {
				return nil // compressed: never accepted
			}
			return p[2:]
		}
	}
	return p
}

// pingString is OpenVPN's keepalive payload.
var pingString = []byte{0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48}

// Writing packets.

// WritePacket encrypts and sends one IP packet.
func (c *Client) WritePacket(ip []byte) error {
	select {
	case <-c.done:
		return c.failure(net.ErrClosed)
	default:
	}
	c.mu.Lock()
	ks, p := c.cur, c.pushed
	var dc dataCipher
	if ks != nil {
		dc = ks.data
	}
	c.mu.Unlock()
	if dc == nil {
		return errors.New("no data key yet")
	}
	plain := ip
	switch c.cfg.Compress {
	case "lzo-no":
		plain = append([]byte{0xFA}, ip...)
	case "stub-v2":
		if len(ip) > 0 && ip[0] == 0x50 {
			plain = append([]byte{0x50, 0}, ip...)
		}
	}
	pid, err := ks.nextPID()
	if err != nil {
		c.end(err)
		return err
	}
	if pid >= rekeyPID {
		c.rekey(ks)
	}
	var pkt []byte
	if p.PeerID >= 0 {
		head := []byte{opDataV2<<3 | ks.id, byte(p.PeerID >> 16), byte(p.PeerID >> 8), byte(p.PeerID)}
		pkt = append(head, dc.seal(pid, head, plain)...)
	} else {
		pkt = append([]byte{opDataV1<<3 | ks.id}, dc.seal(pid, nil, plain)...)
	}
	debugf("data out: %d bytes, pid %d, key %d, peer-id %d", len(ip), pid, ks.id, p.PeerID)
	return c.tr.Write(pkt)
}

// nextPID takes the next send packet id. It never wraps around: the same
// id again would repeat an AEAD nonce under this key.
func (ks *keyState) nextPID() (uint32, error) {
	for {
		pid := ks.sendPID.Load()
		if pid == math.MaxUint32 {
			return 0, errors.New("the data channel ran out of packet ids before the server renegotiated; reconnect")
		}
		if ks.sendPID.CompareAndSwap(pid, pid+1) {
			return pid + 1, nil
		}
	}
}

// sendMsg sends one reliable control message (waiting for a send slot).
func (ks *keyState) sendMsg(op byte, payload []byte) error {
	c := ks.c
	select {
	case <-ks.window:
	case <-c.done:
		return c.failure(net.ErrClosed)
	case <-time.After(60 * time.Second):
		return errors.New("the server stopped acknowledging control packets")
	}
	ks.smu.Lock()
	id := ks.nextID
	ks.nextID++
	m := &sentMsg{op: op, payload: append([]byte{}, payload...), sent: time.Now()}
	ks.unacked[id] = m
	ks.smu.Unlock()
	return ks.transmit(id, m)
}

func (ks *keyState) transmit(id uint32, m *sentMsg) error {
	c := ks.c
	ks.rmu.Lock()
	acks := ks.acks
	if len(acks) > 4 {
		acks = acks[:4]
	}
	ks.acks = ks.acks[len(acks):]
	ks.rmu.Unlock()
	c.mu.Lock()
	rsid := c.remoteSID
	c.mu.Unlock()
	body := encodeBody(ctrlBody{acks: acks, remoteSID: rsid, msgID: id, payload: m.payload, hasMsg: true})
	return c.tr.Write(c.wrap.wrap(m.op<<3|ks.id, c.localSID, body))
}

func (c *Client) retransmitLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		c.mu.Lock()
		keys := c.keys
		c.mu.Unlock()
		for _, ks := range keys {
			if ks == nil {
				continue
			}
			ks.smu.Lock()
			var due []uint32
			for id, m := range ks.unacked {
				wait := time.Duration(1<<min(m.tries, 3)) * 2 * time.Second
				if time.Since(m.sent) > wait {
					m.sent, m.tries = time.Now(), m.tries+1
					due = append(due, id)
				}
			}
			ks.smu.Unlock()
			for _, id := range due {
				ks.smu.Lock()
				m := ks.unacked[id]
				ks.smu.Unlock()
				if m != nil {
					ks.transmit(id, m)
				}
			}
		}
	}
}

func (c *Client) keepalive() {
	for {
		p := c.Pushed()
		select {
		case <-c.done:
			return
		case <-time.After(p.Ping):
		}
		if time.Since(time.Unix(0, c.lastIn.Load())) > p.PingRestart {
			c.fail(errors.New("the server stopped answering (ping-restart)"))
			c.Close()
			return
		}
		c.WritePacket(pingString)
		c.mu.Lock()
		if c.old != nil && time.Now().After(c.oldTill) {
			c.retire(c.old)
			c.old = nil
		}
		c.mu.Unlock()
	}
}

// The TLS stream over the control channel.

type ctrlConn struct{ ks *keyState }

func (cc *ctrlConn) Read(b []byte) (int, error) {
	ks := cc.ks
	ks.rmu.Lock()
	defer ks.rmu.Unlock()
	for ks.inbuf.Len() == 0 {
		if ks.inclose {
			return 0, io.EOF
		}
		ks.incond.Wait()
	}
	return ks.inbuf.Read(b)
}

func (cc *ctrlConn) Write(b []byte) (int, error) {
	for off := 0; off < len(b); off += maxCtrlPayload {
		end := min(off+maxCtrlPayload, len(b))
		if err := cc.ks.sendMsg(opControlV1, b[off:end]); err != nil {
			return off, err
		}
	}
	return len(b), nil
}

// Close ends reads, so a handshake whose context ends stops waiting.
func (cc *ctrlConn) Close() error                       { cc.ks.closeIn(); return nil }
func (cc *ctrlConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (cc *ctrlConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (cc *ctrlConn) SetDeadline(t time.Time) error      { return nil }
func (cc *ctrlConn) SetReadDeadline(t time.Time) error  { return nil }
func (cc *ctrlConn) SetWriteDeadline(t time.Time) error { return nil }

// Transports.

type transport interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}

type udpTransport struct{ c net.Conn }

func (u *udpTransport) Read() ([]byte, error) {
	b := make([]byte, 65536)
	n, err := u.c.Read(b)
	return b[:n], err
}
func (u *udpTransport) Write(p []byte) error { _, err := u.c.Write(p); return err }
func (u *udpTransport) Close() error         { return u.c.Close() }

// tcpTransport frames each packet with a 2-byte length.
type tcpTransport struct {
	c  net.Conn
	mu sync.Mutex
}

func (t *tcpTransport) Read() ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(t.c, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(t.c, b)
	return b, err
}

func (t *tcpTransport) Write(p []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	_, err := t.c.Write(b)
	return err
}
func (t *tcpTransport) Close() error { return t.c.Close() }

func writeString(b *bytes.Buffer, s string) {
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(s)+1))
	b.Write(l[:])
	b.WriteString(s)
	b.WriteByte(0)
}

func readString(r io.Reader) (string, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(l[:])
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\x00"), nil
}

func readFull(ctx context.Context, r io.Reader, b []byte) error {
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(r, b); done <- err }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitFor(ctx context.Context, done <-chan struct{}, ok func() bool) error {
	for !ok() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return net.ErrClosed
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}
