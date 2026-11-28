package cli

import (
	"context"
	"net"
	"testing"
)

// A name that resolves to this computer is this computer: ip6-localhost
// (in the default Debian /etc/hosts), localtest.me (public DNS) and the
// like are refused as localhost is. A name the gate cannot resolve counts
// as here: the gate cannot tell (C655).
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
		"nope.example": true, "web.example": false, "203.0.113.5": false,
	} {
		if got := gateLocalAddr(a); got != want {
			t.Errorf("%q: %v, want %v", a, got, want)
		}
	}
}
