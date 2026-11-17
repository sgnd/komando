package cli

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeResolver answers one MX and one CAA record over TCP, as a server's
// resolver would through the SSH connection.
func fakeResolver(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				io.ReadFull(c, q)
				var m dnsmessage.Message
				if m.Unpack(q) != nil {
					return
				}
				name := m.Questions[0].Name
				resp := dnsmessage.Message{Header: dnsmessage.Header{ID: m.Header.ID, Response: true}, Questions: m.Questions}
				h := dnsmessage.ResourceHeader{Name: name, Type: m.Questions[0].Type, Class: dnsmessage.ClassINET, TTL: 60}
				switch m.Questions[0].Type {
				case dnsmessage.TypeMX:
					mx, _ := dnsmessage.NewName("mail.example.com.")
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.MXResource{Pref: 10, MX: mx}})
				case 257:
					data := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.UnknownResource{Type: 257, Data: data}})
				}
				b, _ := resp.Pack()
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...))
			}()
		}
	}()
	return ln.Addr().String()
}

// Without dig, komando asks the server's resolver itself and writes the
// records as dig +short does.
func TestDNSWithoutDig(t *testing.T) {
	addr := fakeResolver(t)
	dial := func() (net.Conn, error) { return net.Dial("tcp", addr) }
	for typ, want := range map[string]string{"MX": "10 mail.example.com.", "CAA": `0 issue "letsencrypt.org"`} {
		qt, _ := dnsQueryType(typ)
		recs, err := dnsAsk(context.Background(), dial, "example.com", qt)
		if err != nil || len(recs) != 1 || recs[0] != want {
			t.Errorf("%s: %q %v, want %q", typ, recs, err, want)
		}
	}
	if ns := resolvConfServers("#komando:no-dig\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\n# x\n"); len(ns) != 2 || ns[0] != "127.0.0.53" {
		t.Errorf("nameservers %q", ns)
	}
	if got := reverseName(net.ParseIP("10.0.0.5")); got != "5.0.0.10.in-addr.arpa." {
		t.Errorf("reverse %q", got)
	}
}
