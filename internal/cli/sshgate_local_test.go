package cli

import (
	"context"
	"net"
	"strings"
	"testing"
)

// A target the gate cannot find in the inventory is refused for reads as
// for changes, whatever the name resolves to: the gate fails closed (C640).
// A server in the inventory at another address still runs.
func TestGateUnresolvedTargetRefused(t *testing.T) {
	invHome(t)
	gateInventory(t)
	t.Chdir(t.TempDir())
	saved := gateLookup
	t.Cleanup(func() { gateLookup = saved })
	gateLookup = func(_ context.Context, host string) ([]net.IP, error) {
		switch strings.ToLower(strings.TrimSuffix(host, ".")) {
		case "web.example":
			return []net.IP{net.ParseIP("203.0.113.5")}, nil
		case "loop.example":
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	const R = "SSH_GATE_REFUSED"
	for line, want := range map[string]string{
		"logs nosuch.example":                 R, // does not resolve
		"logs web.example":                    R, // resolves, not to this computer
		"logs NoSuch.Example.":                R, // mixed case, trailing dot
		"logs Web.Example.":                   R,
		"logs 'fe80::1%en0'":                  R, // an IPv6 zone that is no loopback
		"fs cat nosuch.example /etc/hostname": R,
		"cache get nosuchconn a":              R,
		"cluster get nosuchconn pods":         R,
		"logs web,nosuch.example":             R, // one unknown part is enough
		"logs loop.example":                   R, // resolves to this computer: as before
		"logs localhost":                      R,
		"logs LocalHost.":                     R,
		"logs 127.0.0.1":                      R,
		"logs '::1'":                          R,
		"logs '[::1]:22'":                     R,
		"logs 'fe80::1%lo0'":                  R,
		"logs web":                            "", // in the inventory, elsewhere
		"logs Web":                            "",
		"fs cat web /etc/hostname":            "",
	} {
		for _, readOnly := range []bool{true, false} {
			if got := gateAnswer(t, line, readOnly); got != want {
				t.Errorf("%q (read-only key %v): %q, want %q", line, readOnly, got, want)
			}
		}
	}
	words, err := gateWords("logs nosuch.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, e := gateCheck(words, gateKey{readOnly: true}); e == nil || !strings.Contains(e.Message, `the gate cannot tell where "nosuch.example" is`) {
		t.Errorf("logs nosuch.example: %+v", e)
	}
}
