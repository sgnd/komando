package netx

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// A bad pid must never reach kill(2): -1 signals every process of the
// user, 0 the process group, 1 init.
func TestTerminateRefusesDangerousPids(t *testing.T) {
	for _, pid := range []int{-1, 0, 1, os.Getpid()} {
		if err := Terminate(pid); err == nil {
			t.Errorf("Terminate(%d) must refuse", pid)
		}
		if pid != os.Getpid() && Alive(pid) {
			t.Errorf("Alive(%d) must be false", pid)
		}
	}
	StopSession(&store.VpnSession{PID: -1}) // must do nothing (the test process survives)
	StopSession(&store.VpnSession{PID: 0})
}

func TestRoutesAndClashes(t *testing.T) {
	before := parseNetstat(`Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.100.1      UGScg                 en0
10/8               10.20.0.1          UGSc                utun3
127                127.0.0.1          UCS                   lo0
192.168.100        link#11            UCS                   en0      !
192.168.100.1/32   link#11            UCS                   en0      !
`)
	if len(before) != 4 || before[0].Prefix.String() != "10.0.0.0/8" || before[2].Prefix.String() != "192.168.100.0/24" {
		t.Fatalf("netstat parse: %+v", before)
	}
	after := append(append([]Route{}, before...), Route{Prefix: netip.MustParsePrefix("10.8.0.0/24"), Iface: "utun4"},
		Route{Prefix: netip.MustParsePrefix("172.16.5.0/24"), Iface: "utun4"})
	w := Clashes(before, after)
	if len(w) != 1 || !strings.Contains(w[0], "10.8.0.0/24") || !strings.Contains(w[0], "utun3") {
		t.Errorf("clashes: %v", w)
	}
	lin := parseIPRoute("default via 10.0.2.2 dev eth0\n10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.2\n172.17.0.0/16 dev docker0\n")
	if len(lin) != 2 || lin[0].Iface != "tun0" {
		t.Errorf("ip route parse: %+v", lin)
	}
}

func TestDownHintsPerKind(t *testing.T) {
	for kind, want := range map[string]string{"socks": "tunnel start HOST -D 127.0.0.1:1080", "system": "connect the VPN", "wireguard": "endpoint", "tailscale": "vpn up x"} {
		h := DownHint(&store.Vpn{Name: "x", Kind: kind, Address: "127.0.0.1:1080"})
		if !strings.Contains(h, want) || strings.Contains(h, "komando test x") {
			t.Errorf("%s: %q", kind, h)
		}
	}
	err := socksErr("127.0.0.1:1080", errors.New("socks connect tcp 127.0.0.1:1080->pg:5432: dial tcp 127.0.0.1:1080: connect: connection refused"))
	if !strings.Contains(err.Error(), "SOCKS proxy at 127.0.0.1:1080 is not running") {
		t.Fatal(err)
	}
	werr := wgDialErr(context.DeadlineExceeded, "10.0.0.5:22", "vpn.example.com:51820", 15*time.Second)
	if werr.Error() != "no answer from 10.0.0.5:22 within 15s: no WireGuard handshake from vpn.example.com:51820; check its endpoint, its public key and that UDP gets through" {
		t.Fatal(werr)
	}
	if SecretHint("secret:wg-key") != "store it with `komando secret set wg-key`" {
		t.Fatal(SecretHint("secret:wg-key"))
	}
}

func TestBuiltinSSL(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no openconnect: every SSL VPN kind komando speaks is built in
	for _, k := range []string{"anyconnect", "fortinet", "globalprotect", "f5", "pulse"} {
		if !BuiltinSSL(k) {
			t.Errorf("%s without openconnect is not built in", k)
		}
	}
	if BuiltinSSL("openvpn") || BuiltinSSL("nope") {
		t.Error("not an SSL VPN kind")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "openconnect"), []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("PATH", dir)
	if BuiltinSSL("pulse") || !BuiltinSSL("anyconnect") {
		t.Error("with openconnect installed, only tested kinds are built in")
	}
	t.Setenv("KOMANDO_EXPERIMENTAL_VPN", "pulse")
	if !BuiltinSSL("pulse") || BuiltinSSL("f5") {
		t.Error("KOMANDO_EXPERIMENTAL_VPN names the kinds to use")
	}
}
