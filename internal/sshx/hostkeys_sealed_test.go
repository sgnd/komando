package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/store"
)

func newHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pinHome makes a fresh home.
func pinHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	t.Setenv("KOMANDO_VAULT_PASS", "")
}

type checkCase struct {
	name     string
	host     string // the hostname komando dialled ("" for none)
	remote   string
	key      int // which key the server offers
	want     string
	wantKeys int // keys in Want for a refused key
}

// The sealed store answers every check exactly as known_hosts does.
func TestPinsSameOnBothBackends(t *testing.T) {
	keys := []ssh.PublicKey{newHostKey(t), newHostKey(t), newHostKey(t)}
	pins := []struct {
		addr string
		key  int
	}{
		{"web.example.com:22", 0},
		{"10.0.0.5:2222", 1},
		{"[2001:db8::1]:22", 2},
		{"multi:22", 0},
		{"multi:22", 1},
	}
	cases := []checkCase{
		{"known host", "web.example.com:22", "10.0.0.9:22", 0, "ok", 0},
		{"host changed key", "web.example.com:22", "10.0.0.9:22", 1, "changed", 1},
		{"unknown host", "new.example.com:22", "10.0.0.9:22", 0, "unknown", 0},
		{"by remote address", "", "10.0.0.5:2222", 1, "ok", 0},
		{"other port is another server", "10.0.0.5:22", "10.0.0.5:22", 1, "unknown", 0},
		{"hostname wins over a pinned ip", "other:22", "10.0.0.5:2222", 1, "unknown", 0},
		{"ipv6", "[2001:db8::1]:22", "[2001:db8::1]:22", 2, "ok", 0},
		{"ipv6 changed", "[2001:db8::1]:22", "[2001:db8::1]:22", 0, "changed", 1},
		{"two pins, second matches", "multi:22", "1.1.1.1:22", 1, "ok", 0},
		{"two pins, neither", "multi:22", "1.1.1.1:22", 2, "changed", 2},
		{"host names are compared as written", "WEB.example.com:22", "10.0.0.9:22", 0, "unknown", 0},
	}
	pinHome(t)
	for _, p := range pins {
		if _, err := PinHostKey(p.addr, keys[p.key], false); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range cases {
		remote, err := net.ResolveTCPAddr("tcp", c.remote)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		_ = HostKeys().view(func(tx hostKeyTx) error {
			err := tx.Check(c.host, remote, keys[c.key])
			var ke *knownhosts.KeyError
			switch {
			case err == nil:
				got = "ok"
			case errors.As(err, &ke) && len(ke.Want) == 0:
				got = "unknown"
			case errors.As(err, &ke):
				got = "changed/" + string(rune('0'+len(ke.Want)))
			default:
				got = "error: " + err.Error()
			}
			return nil
		})
		want := c.want
		if want == "changed" {
			want += "/" + string(rune('0'+c.wantKeys))
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", c.name, got, want)
		}
	}
}

func TestSealedPinChanges(t *testing.T) {
	pinHome(t)
	a, b := newHostKey(t), newHostKey(t)
	if pins, _ := PinnedKeys("h:22"); len(pins) != 0 {
		t.Fatal("pins before any")
	}
	if _, err := os.Stat(store.Path(store.StoreFile)); !os.IsNotExist(err) {
		t.Fatal("a read made the store")
	}
	if _, err := PinHostKey("h:22", a, false); err != nil {
		t.Fatal(err)
	}
	if _, err := PinHostKey("h:22", a, false); err != nil { // already there
		t.Fatal(err)
	}
	if n, _ := CountPinned("h:22"); n != 1 {
		t.Fatalf("count %d", n)
	}
	if _, err := PinHostKey("h:22", b, false); err != nil {
		t.Fatal(err)
	}
	removed, err := PinHostKey("h:22", b, true)
	if err != nil || removed != 1 {
		t.Fatalf("replace removed %d %v", removed, err)
	}
	pins, _ := PinnedKeys("h:22")
	if len(pins) != 1 || !SameKey(pins[0], b) {
		t.Fatalf("pins after replace %v", pins)
	}
	if _, err := os.Stat(store.Path("known_hosts")); !os.IsNotExist(err) {
		t.Fatal("known_hosts written in a sealed home")
	}
}

// A revoked key is refused for every server, and can never be pinned.
func TestRevokedHostKey(t *testing.T) {
	pinHome(t)
	keys := []ssh.PublicKey{newHostKey(t), newHostKey(t)}
	if _, err := PinHostKey("web:22", keys[0], false); err != nil {
		t.Fatal(err)
	}
	if err := RevokeHostKeys([]ssh.PublicKey{keys[0], keys[1]}); err != nil {
		t.Fatal(err)
	}
	remote, _ := net.ResolveTCPAddr("tcp", "10.0.0.1:22")
	for _, host := range []string{"web:22", "other:22"} {
		_ = HostKeys().view(func(tx hostKeyTx) error {
			var rv *knownhosts.RevokedError
			if err := tx.Check(host, remote, keys[0]); !errors.As(err, &rv) {
				t.Errorf("%s: %v", host, err)
			}
			return nil
		})
	}
	if _, err := PinHostKey("new:22", keys[1], false); err == nil {
		t.Error("a revoked key was pinned")
	}
	if rev, _ := HostKeyRevoked(keys[1]); !rev {
		t.Error("not on the list")
	}
}

// A sealed folder whose store.db is gone never reads as "no pins": that
// would trust any key again (review S2).
func TestPinsOfMissingStore(t *testing.T) {
	pinHome(t)
	if _, err := PinHostKey("web:22", newHostKey(t), false); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(store.DBPath(), store.DBPath()+".gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := PinnedKeys("web:22"); err == nil || !strings.Contains(err.Error(), "STATE_CORRUPT") {
		t.Fatalf("missing store read as no pins: %v", err)
	}
}
