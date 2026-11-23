package capability

import "testing"

// TestPSKGenerated: the WireGuard preshared key is the post-quantum layer,
// so komando makes it at 256 bits and nobody types it.
func TestPSKGenerated(t *testing.T) {
	for _, verb := range []string{"add", "edit"} {
		l, ok := Find(Key{Type: "vpn", Provider: "wireguard", Verb: verb})
		if !ok {
			t.Fatalf("no vpn wireguard %s", verb)
		}
		o, ok := l.Option("psk-credential")
		if !ok || !o.Generated || o.Kind != Credential {
			t.Errorf("vpn wireguard %s --psk-credential: %+v, want a generated credential", verb, o)
		}
		if _, typed := l.Option("psk"); typed {
			t.Errorf("vpn wireguard %s: a typed --psk must not exist", verb)
		}
	}
}
