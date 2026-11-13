package openvpn

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func staticKeyBlock(k []byte) string {
	h := hex.EncodeToString(k)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(h); i += 32 {
		b.WriteString(h[i:i+32] + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

func TestParse(t *testing.T) {
	key := make([]byte, 256)
	rand.Read(key)
	profile := `client
dev tun
proto udp
remote vpn.example.com 1194
remote vpn2.example.com 443 tcp
remote-cert-tls server
cipher AES-256-GCM
data-ciphers AES-256-GCM:CHACHA20-POLY1305
auth SHA256
auth-user-pass
key-direction 1
setenv UV_ID abc123
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<tls-auth>
` + staticKeyBlock(key) + `</tls-auth>
`
	c, err := Parse(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Remotes) != 2 || c.Remotes[0] != (Remote{"vpn.example.com", "1194", "udp"}) || c.Remotes[1] != (Remote{"vpn2.example.com", "443", "tcp"}) {
		t.Errorf("remotes %+v", c.Remotes)
	}
	if !c.RemoteCertTLS || !c.AuthUserPass || c.Auth != "SHA256" || c.KeyDirection != 1 || !bytes.Equal(c.TLSAuth, key) ||
		strings.Join(c.Ciphers, ":") != "AES-256-GCM:CHACHA20-POLY1305" || c.Setenv["UV_ID"] != "abc123" {
		t.Errorf("parsed %+v", c)
	}
	for _, bad := range []struct{ line, want string }{
		{"comp-lzo yes", "VORACLE"},
		{"compress lz4-v2", "VORACLE"},
		{"dev tap", "tap"},
		{"tls-crypt-v2 [inline]", "not supported"},
		{"ca /etc/openvpn/ca.crt", "inline"},
		{"auth-user-pass /etc/pass", "--password-ref"},
		{"frobnicate yes", "does not know the option frobnicate"},
		{"cipher BF-CBC", "not supported"},
	} {
		if _, err := Parse(profile + bad.line + "\n"); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q: %v, want %q", bad.line, err, bad.want)
		}
	}
	if _, err := Parse("client\nremote x 1194\n"); err == nil || !strings.Contains(err.Error(), "<ca>") {
		t.Errorf("no ca: %v", err)
	}
}

func TestFields(t *testing.T) {
	got := fields(`setenv UV_NAME "my laptop" # comment`)
	if strings.Join(got, "|") != "setenv|UV_NAME|my laptop" {
		t.Errorf("%q", got)
	}
}

// the server's side of a wrapper uses the opposite key direction
func TestControlWraps(t *testing.T) {
	key := make([]byte, 256)
	rand.Read(key)
	var sid [8]byte
	copy(sid[:], "session1")
	body := []byte("acks, message id and TLS bytes")

	client, _ := newAuthWrap(key, 1, "SHA256")
	server, _ := newAuthWrap(key, 0, "SHA256")
	pkt := client.wrap(opControlV1<<3, sid, body)
	op, gotSID, got, err := server.unwrap(pkt)
	if err != nil || op != opControlV1<<3 || gotSID != sid || !bytes.Equal(got, body) {
		t.Fatalf("tls-auth: %v", err)
	}
	if _, _, _, err := server.unwrap(pkt); err == nil {
		t.Error("tls-auth must refuse a replayed packet")
	}
	pkt = client.wrap(opControlV1<<3, sid, body)
	pkt[len(pkt)-1] ^= 1
	if _, _, _, err := server.unwrap(pkt); err == nil {
		t.Error("tls-auth must refuse a changed packet")
	}
	wrong, _ := newAuthWrap(key, 1, "SHA256") // same direction as the sender
	if _, _, _, err := wrong.unwrap(client.wrap(opControlV1<<3, sid, body)); err == nil {
		t.Error("the wrong key direction must not verify")
	}

	cc := newCryptWrap(key)
	send, recv := keyPair(key, 0)
	sc := &cryptWrap{sendKey: send.cipher[:32], recvKey: recv.cipher[:32], sendMAC: send.hmac[:32], recvMAC: recv.hmac[:32]}
	pkt = cc.wrap(opControlV1<<3, sid, body)
	if bytes.Contains(pkt, body) {
		t.Error("tls-crypt must encrypt the body")
	}
	if _, _, got, err := sc.unwrap(pkt); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("tls-crypt: %v", err)
	}
	back := sc.wrap(opAckV1<<3, sid, []byte("ack"))
	if _, _, got, err := cc.unwrap(back); err != nil || string(got) != "ack" {
		t.Fatalf("tls-crypt back: %v", err)
	}
}

func TestBody(t *testing.T) {
	var rsid [8]byte
	copy(rsid[:], "remote!!")
	b := ctrlBody{acks: []uint32{3, 4}, remoteSID: rsid, msgID: 7, payload: []byte("tls"), hasMsg: true}
	got, err := decodeBody(opControlV1<<3, encodeBody(b))
	if err != nil || len(got.acks) != 2 || got.acks[1] != 4 || got.remoteSID != rsid || got.msgID != 7 || string(got.payload) != "tls" {
		t.Errorf("%+v %v", got, err)
	}
	ack, err := decodeBody(opAckV1<<3, encodeBody(ctrlBody{acks: []uint32{9}, remoteSID: rsid}))
	if err != nil || ack.hasMsg || ack.acks[0] != 9 {
		t.Errorf("ack %+v %v", ack, err)
	}
}

func TestDataCiphers(t *testing.T) {
	material := make([]byte, 256)
	rand.Read(material)
	for _, name := range []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC", "AES-128-CBC"} {
		client, err := newDataCipher(name, "SHA256", material)
		if err != nil {
			t.Fatal(err)
		}
		// the server's view: slot 1 sends, slot 0 receives
		ssend, srecv := keyPair(material, 1)
		var server dataCipher
		if strings.HasSuffix(name, "CBC") {
			server, _ = newCBC(name, "SHA256", ssend, srecv)
		} else {
			server, _ = newAEAD(name, ssend, srecv)
		}
		ad := []byte{opDataV2 << 3, 0, 0, 1}
		pkt := client.seal(42, ad, []byte("an IP packet"))
		pid, plain, err := server.open(ad, pkt)
		if err != nil || pid != 42 || string(plain) != "an IP packet" {
			t.Errorf("%s client->server: %d %q %v", name, pid, plain, err)
		}
		pkt = server.seal(7, ad, []byte("reply"))
		if pid, plain, err := client.open(ad, pkt); err != nil || pid != 7 || string(plain) != "reply" {
			t.Errorf("%s server->client: %v", name, err)
		}
		pkt[len(pkt)-1] ^= 1
		if _, _, err := client.open(ad, pkt); err == nil {
			t.Errorf("%s must refuse a changed packet", name)
		}
	}
}

func TestReplay(t *testing.T) {
	var r replay
	for _, c := range []struct {
		pid uint32
		ok  bool
	}{{1, true}, {2, true}, {2, false}, {5, true}, {3, true}, {3, false}, {100, true}, {30, false}, {99, true}} {
		if got := r.ok(c.pid); got != c.ok {
			t.Errorf("pid %d: %v, want %v", c.pid, got, c.ok)
		}
	}
}

// TestPRF checks the TLS 1.0 PRF (MD5 xor SHA-1) against OpenSSL; the
// secret's odd length checks that its halves share the middle byte.
func TestPRF(t *testing.T) {
	a := prf([]byte("secret"), "label", []byte("seed"), 48)
	b := prf([]byte("secret"), "label", []byte("seed"), 48)
	c := prf([]byte("secreT"), "label", []byte("seed"), 48)
	if len(a) != 48 || !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Error("prf is not deterministic or ignores the secret")
	}
	// the same inputs through OpenSSL: openssl kdf -keylen 48 -kdfopt
	// digest:MD5-SHA1 -kdfopt hexsecret:0001..14 -kdfopt hexseed:LABEL||a1a2a3a4 TLS1-PRF
	secret, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314")
	seed, _ := hex.DecodeString("a1a2a3a4")
	want := "e3dd328060edf8ae9132eb04274bfee9b9901344db0ff5e477beec9e2a7354e8c690ce3c38261af567b56cf35488e6f0"
	if got := hex.EncodeToString(prf(secret, "OpenVPN master secret", seed, 48)); got != want {
		t.Errorf("prf = %s\nwant  %s", got, want)
	}
}
