package openvpn

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// The parsers that read what a profile file or the network sends must not
// panic, whatever comes in.

func FuzzParse(f *testing.F) {
	f.Add("client\nremote x 1194\n<ca>\nx\n</ca>\nauth-user-pass\n")
	f.Add("<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nzz\n-----END OpenVPN Static key V1-----\n</tls-auth>")
	f.Add(`setenv UV_NAME "a b" \x`)
	f.Fuzz(func(t *testing.T, s string) { Parse(s) })
}

func FuzzPackets(f *testing.F) {
	key := make([]byte, 256)
	rand.Read(key)
	f.Add([]byte{opControlV1 << 3, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0})
	f.Add([]byte{opAckV1 << 3, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 9})
	aw, _ := newAuthWrap(key, 0, "SHA1")
	cw := newCryptWrap(key)
	dc, _ := newDataCipher("AES-256-GCM", "SHA1", key)
	cbc, _ := newDataCipher("AES-256-CBC", "SHA256", key)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 0 {
			decodeBody(b[0], b)
		}
		plainWrap{}.unwrap(b)
		aw.unwrap(b)
		cw.unwrap(b)
		dc.open(nil, b)
		cbc.open(nil, b)
	})
}

// A pushed ping or ping-restart too large for a Duration overflowed to a
// negative one, and the keepalive loop spun without waiting.
func TestPushedPingClamped(t *testing.T) {
	c := &Client{cfg: &Config{Ciphers: []string{"AES-256-GCM"}}}
	p := c.parsePush([]string{"cipher AES-256-GCM", "ping 9223372036854775807", "ping-restart 99999999999999"})
	if p.Ping <= 0 || p.Ping > 24*time.Hour || p.PingRestart <= 0 || p.PingRestart > 24*time.Hour {
		t.Fatalf("ping %v, ping-restart %v", p.Ping, p.PingRestart)
	}
	if p = c.parsePush([]string{"cipher AES-256-GCM", "ping 5", "ping-restart -1"}); p.Ping != 5*time.Second || p.PingRestart != 120*time.Second {
		t.Fatalf("ping %v, ping-restart %v", p.Ping, p.PingRestart)
	}
}

// What a server pushes must not panic the client.
func FuzzPush(f *testing.F) {
	f.Add("ifconfig 10.8.0.2 255.255.255.0,route 10.0.0.0 255.0.0.0,ping 10,cipher AES-256-GCM")
	f.Fuzz(func(t *testing.T, s string) {
		c := &Client{cfg: &Config{Ciphers: []string{"AES-256-GCM"}}, done: make(chan struct{})}
		c.parsePush(strings.Split(s, ","))
	})
}
