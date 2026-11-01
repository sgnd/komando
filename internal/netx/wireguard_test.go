package netx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func keypair(t *testing.T) (priv, pub string) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(p)
}

func hx(t *testing.T, b64 string) string {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// TestWireGuardEndToEnd runs a WireGuard "server" and komando's client in
// one process over loopback UDP, then sends TCP through the tunnel.
func TestWireGuardEndToEnd(t *testing.T) {
	srvPriv, srvPub := keypair(t)
	cliPriv, cliPub := keypair(t)

	// server: 10.77.0.1, UDP on a free port, a TCP echo on :7
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	sdev := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer sdev.Close()
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.77.0.2/32\n", hx(t, srvPriv), port, hx(t, cliPub))); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := snet.ListenTCP(&net.TCPAddr{Port: 7})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.77.0.2/32
PostUp = this line is ignored

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.77.0.0/24
`, cliPriv, srvPub, port)

	clean, priv, psk, err := StripWGKeys(conf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clean, cliPriv) || priv != cliPriv || psk != "" {
		t.Fatalf("keys must be taken out of the stored config")
	}
	c, err := ParseWG(clean)
	if err != nil {
		t.Fatal(err)
	}
	c.PrivateKey = priv
	dial, closer, err := StartWG(c)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, err := dial(ctx, "tcp", "10.77.0.1:7")
	if err != nil {
		t.Fatalf("dial through WireGuard: %v", err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(nc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through WireGuard: %q %v", buf, err)
	}
}

func TestParseWGErrors(t *testing.T) {
	for _, bad := range []string{
		"[Interface]\nPrivateKey = x\n",        // no address
		"[Interface]\nAddress = 10.0.0.2/32\n", // no peer
		"[Interface]\nAddress = nope\n[Peer]\nPublicKey = x\nAllowedIPs = 0.0.0.0/0\n",
		"[Interface]\nAddress = 10.0.0.2\n[Peer]\nAllowedIPs = 0.0.0.0/0\n", // no PublicKey
	} {
		if _, err := ParseWG(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}
