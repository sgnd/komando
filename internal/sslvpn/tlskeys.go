package sslvpn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"hash"
	"net"
	"strings"
	"sync"
)

// tlsKeys keeps what the TLS 1.2 exporter (RFC 5705) needs from one
// connection komando made itself: the master secret (Go hands it to the
// connection's own KeyLogWriter; nothing is written anywhere) and both
// hello randoms (the server's read from its ServerHello, which TLS 1.2
// sends in the clear).
type tlsKeys struct {
	mu                         sync.Mutex
	master, clientRandom, srvR []byte
}

// Write takes the key log line "CLIENT_RANDOM <client random> <master secret>".
func (k *tlsKeys) Write(b []byte) (int, error) {
	f := strings.Fields(string(b))
	if len(f) == 3 && f[0] == "CLIENT_RANDOM" {
		cr, err1 := hex.DecodeString(f[1])
		ms, err2 := hex.DecodeString(f[2])
		if err1 == nil && err2 == nil {
			k.mu.Lock()
			k.clientRandom, k.master = cr, ms
			k.mu.Unlock()
		}
	}
	return len(b), nil
}

// export is the RFC 5705 exporter without a context, for TLS 1.2:
// PRF(master secret, label, client random + server random), the PRF on
// the cipher suite's hash.
func (k *tlsKeys) export(st tls.ConnectionState, label string, n int) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if st.Version != tls.VersionTLS12 || len(k.master) != 48 || len(k.clientRandom) != 32 || len(k.srvR) != 32 {
		return nil, errors.New("no TLS 1.2 keys for the exporter")
	}
	h := sha256.New
	if strings.HasSuffix(tls.CipherSuiteName(st.CipherSuite), "SHA384") {
		h = sha512.New384
	}
	seed := append(append([]byte(label), k.clientRandom...), k.srvR...)
	return prf12(h, k.master, seed, n), nil
}

// prf12 is the TLS 1.2 PRF (RFC 5246 section 5), P_hash.
func prf12(h func() hash.Hash, secret, seed []byte, n int) []byte {
	out := make([]byte, 0, n+64)
	mac := hmac.New(h, secret)
	a := seed
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out)
	}
	return out[:n]
}

// helloSniffer reads the server random out of the first handshake
// records the server sends, then just passes bytes through.
type helloSniffer struct {
	net.Conn
	keys *tlsKeys
	buf  []byte // TLS records read so far, until the ServerHello is found
	done bool
}

func (s *helloSniffer) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if !s.done && n > 0 {
		s.buf = append(s.buf, p[:n]...)
		s.look()
	}
	return n, err
}

// look joins the handshake records' payloads and, once the ServerHello is
// there, keeps its random (bytes 6..38 of the message).
func (s *helloSniffer) look() {
	var hs []byte
	b := s.buf
	for len(b) >= 5 {
		l := int(b[3])<<8 | int(b[4])
		if len(b) < 5+l {
			break
		}
		if b[0] != 22 { // not a handshake record: no plain ServerHello coming
			s.stop()
			return
		}
		hs = append(hs, b[5:5+l]...)
		b = b[5+l:]
	}
	if len(hs) >= 38 {
		if hs[0] == 2 { // ServerHello
			s.keys.mu.Lock()
			s.keys.srvR = bytes.Clone(hs[6:38])
			s.keys.mu.Unlock()
		}
		s.stop()
		return
	}
	if len(s.buf) > 64<<10 {
		s.stop()
	}
}

func (s *helloSniffer) stop() { s.done, s.buf = true, nil }
