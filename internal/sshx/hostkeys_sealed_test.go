package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
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

// pinHome makes a home on the file backend or the sealed store.
func pinHome(t *testing.T, sealed bool) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	t.Setenv("KOMANDO_VAULT_PASS", "")
	store.UseSealedForNewHomes(sealed)
	t.Cleanup(func() { store.UseSealedForNewHomes(false) })
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
	results := map[bool][]string{}
	for _, sealed := range []bool{false, true} {
		pinHome(t, sealed)
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
				t.Errorf("sealed=%v %s: got %s, want %s", sealed, c.name, got, want)
			}
			results[sealed] = append(results[sealed], got)
		}
	}
	if strings.Join(results[false], ",") != strings.Join(results[true], ",") {
		t.Fatalf("backends differ:\nfile   %v\nsealed %v", results[false], results[true])
	}
}

func TestSealedPinChanges(t *testing.T) {
	pinHome(t, true)
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

// dialPin runs the host key check as a connection does, with the policy
// that pins a new server on first use.
func dialPin(t *testing.T, key ssh.PublicKey) error {
	t.Helper()
	cb, err := hostKeyCallback("web", "accept-new")
	if err != nil {
		t.Fatal(err)
	}
	return cb("web.example.com:22", &net.TCPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 22}, key)
}

// A pin removed from the store with plain sqlite stops the connection; it
// is never pinned again on first use.
func TestSealedPinRowRemoved(t *testing.T) {
	pinHome(t, true)
	if _, err := PinHostKey("web.example.com:22", newHostKey(t), false); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`DELETE FROM records WHERE type=?`, pinType); err != nil {
		t.Fatal(err)
	}
	if err := dialPin(t, newHostKey(t)); !errors.Is(err, sealdb.ErrTampered) {
		t.Fatalf("a removed pin let a new key in: %v", err)
	}
}

// A pin that cannot be read stops the connection with HOSTKEY_UNREADABLE.
func TestSealedPinUnreadable(t *testing.T) {
	pinHome(t, true)
	d, err := store.DB(true)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := json.Marshal(pinRecord{Addr: knownhosts.Normalize("web.example.com:22"), Keys: []string{"not a key"}})
	if err := d.Update(context.Background(), func(tx *sealdb.Tx) error { _, err := tx.Put(pinType, "", rec); return err }); err != nil {
		t.Fatal(err)
	}
	var oe *out.Error
	if err := dialPin(t, newHostKey(t)); !errors.As(err, &oe) || oe.Code != "HOSTKEY_UNREADABLE" {
		t.Fatalf("an unreadable pin: %v", err)
	}
}
