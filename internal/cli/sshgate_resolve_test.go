package cli

import (
	"context"
	"net"
	"testing"
)

// A name that resolves to this computer is this computer: ip6-localhost
// (in the default Debian /etc/hosts), localtest.me (public DNS) and the
// like are refused as localhost is. A name the gate cannot resolve is
// judged as written.
func TestGateLocalAddrResolvesNames(t *testing.T) {
	saved := gateLookup
	t.Cleanup(func() { gateLookup = saved })
	gateLookup = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "ip6-localhost":
			return []net.IP{net.ParseIP("::1")}, nil
		case "localtest.me":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		case "mixed.example":
			return []net.IP{net.ParseIP("203.0.113.5"), net.ParseIP("0.0.0.0")}, nil
		case "web.example":
			return []net.IP{net.ParseIP("203.0.113.5")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	for a, want := range map[string]bool{
		"ip6-localhost": true, "ip6-localhost:8443": true, "localtest.me": true, "mixed.example": true,
		"web.example": false, "nope.example": false, "203.0.113.5": false,
	} {
		if got := gateLocalAddr(a); got != want {
			t.Errorf("%q: %v, want %v", a, got, want)
		}
	}
	invHome(t)
	if gateAnswer(t, "cert check https://ip6-localhost:8443", true) == "" {
		t.Error("cert check https://ip6-localhost allowed by the gate")
	}
	if c := gateAnswer(t, "cert check https://web.example", true); c != "" {
		t.Errorf("cert check of a website refused: %s", c)
	}
}

// What a gated cert check dials is checked again when it connects: a name
// whose answer changed after the gate looked at it (DNS rebinding) still
// cannot reach this computer.
func TestGateCertDialRefusesThisComputer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
			c.Close()
		}
	}()
	dial := func() error {
		cl := testCall()
		d, _, err := certDialer(cl, context.Background(), nil, "")
		if err != nil {
			return err
		}
		c, err := d(context.Background(), "tcp", ln.Addr().String())
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		t.Fatalf("a person's cert check: %v", err)
	}
	setCallerEnv(t, gateEnv, "phone")
	if err := dial(); err == nil {
		t.Fatal("a gated cert check reached a loopback port")
	}
}
