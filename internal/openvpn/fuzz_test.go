package openvpn

import (
	"crypto/rand"
	"testing"
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
