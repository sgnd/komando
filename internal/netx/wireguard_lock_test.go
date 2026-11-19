package netx

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func testKeyLock(t *testing.T) (dir, private, public string) {
	t.Helper()
	dir = t.TempDir()
	old := KeyLockDir
	KeyLockDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { KeyLockDir = old })
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	pub, _ := curve25519.X25519(k, curve25519.Basepoint)
	return dir, base64.StdEncoding.EncodeToString(k), base64.StdEncoding.EncodeToString(pub)
}

func TestWGPublicKey(t *testing.T) {
	_, priv, pub := testKeyLock(t)
	got, err := WGPublicKey(priv)
	if err != nil || got != pub {
		t.Fatalf("WGPublicKey = %q, %v; want %q", got, err, pub)
	}
	if _, err := WGPublicKey("bm90IGEga2V5"); err == nil {
		t.Fatal("a short key was taken")
	}
}

// A live holder blocks another process; the record has the public key only.
func TestClaimKeyLiveHolder(t *testing.T) {
	dir, priv, pub := testKeyLock(t)
	self := KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: ProcessStart(os.Getpid()), Socks: "127.0.0.1:1080", Home: "/a", Vpn: "office"}
	if other, err := ClaimKey(self); err != nil || other != nil {
		t.Fatalf("first claim: %v, %v", other, err)
	}
	other, err := ClaimKey(KeyHolder{PublicKey: pub, PID: os.Getpid() + 100000, Home: "/b", Vpn: "office2"})
	if err != nil || other == nil || other.Home != "/a" || other.Socks != "127.0.0.1:1080" {
		t.Fatalf("second claim: %+v, %v; want the first holder", other, err)
	}
	if h, _ := KeyInUse(pub); h == nil || h.Vpn != "office" {
		t.Fatalf("KeyInUse = %+v", h)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		raw, _ := base64.StdEncoding.DecodeString(priv)
		if strings.Contains(string(b), priv) || strings.Contains(string(b), string(raw)) {
			t.Fatalf("%s holds the private key", f)
		}
	}
	if err := ReleaseKey(pub, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	if h, _ := KeyInUse(pub); h != nil {
		t.Fatalf("after release: %+v", h)
	}
}

// A record whose process has ended is taken over.
func TestClaimKeyStale(t *testing.T) {
	_, _, pub := testKeyLock(t)
	c := exec.Command(os.Args[0], "-test.run=^$")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	gone := c.Process.Pid
	if _, err := ClaimKey(KeyHolder{PublicKey: pub, PID: gone, ProcStart: "1.0", Home: "/old", Vpn: "office"}); err != nil {
		t.Fatal(err)
	}
	if h, _ := KeyInUse(pub); h != nil {
		t.Fatalf("an ended process counts as live: %+v", h)
	}
	other, err := ClaimKey(KeyHolder{PublicKey: pub, PID: os.Getpid(), ProcStart: ProcessStart(os.Getpid()), Home: "/new", Vpn: "office"})
	if err != nil || other != nil {
		t.Fatalf("take over: %+v, %v", other, err)
	}
	if h, _ := KeyInUse(pub); h == nil || h.Home != "/new" {
		t.Fatalf("after take over: %+v", h)
	}
}

func TestLastHandshake(t *testing.T) {
	dump := "public_key=aa\nlast_handshake_time_sec=0\npublic_key=bb\nlast_handshake_time_sec=1700000100\nlast_handshake_time_nsec=5\n"
	if got := lastHandshake(dump); got.Unix() != 1700000100 {
		t.Fatalf("lastHandshake = %v", got)
	}
	if got := lastHandshake("last_handshake_time_sec=0\n"); !got.IsZero() {
		t.Fatalf("no handshake = %v", got)
	}
}
