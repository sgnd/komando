package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// keySSHD is a loopback SSH server that shows whatever host key is in key
// at the time a client connects (a rebuilt server, or an impostor).
func keySSHD(t *testing.T, key *atomic.Pointer[ssh.Signer]) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			cfg := &ssh.ServerConfig{NoClientAuth: true}
			cfg.AddHostKey(*key.Load())
			go func() {
				if sc, _, _, err := ssh.NewServerConn(nc, cfg); err == nil {
					sc.Close()
				}
				nc.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func trustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pinnedFingerprints lists what known_hosts pins for addr.
func pinnedFingerprints(t *testing.T, addr string) []string {
	t.Helper()
	pins, err := sshx.PinnedKeys(addr)
	if err != nil {
		t.Fatal(err)
	}
	var fps []string
	for _, k := range pins {
		fps = append(fps, ssh.FingerprintSHA256(k))
	}
	return fps
}

// trustLab adds the protected host prod1 at a server whose key the test
// can swap, pins the real key and returns the address and both keys.
func trustLab(t *testing.T) (addr string, key *atomic.Pointer[ssh.Signer], real, impostor ssh.Signer) {
	t.Helper()
	invHome(t)
	real, impostor = trustSigner(t), trustSigner(t)
	key = new(atomic.Pointer[ssh.Signer])
	key.Store(&real)
	port := keySSHD(t, key)
	addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	mustRun(t, "host", "add", "prod1", "root@"+addr, "--protected")
	d := mustRun(t, "host", "trust", "prod1")
	if d["fingerprint"] != ssh.FingerprintSHA256(real.PublicKey()) {
		t.Fatalf("first pin: %v", d)
	}
	return addr, key, real, impostor
}

// host trust compares the key it fetched with the pinned one: the same key
// is a no-op, a different key is HOSTKEY_MISMATCH (never a second pin), and
// replacing the pin needs --yes. A failed fetch keeps the old pin.
func TestHostTrustNeverRepinsSilently(t *testing.T) {
	addr, key, real, impostor := trustLab(t)
	realFP, impFP := ssh.FingerprintSHA256(real.PublicKey()), ssh.FingerprintSHA256(impostor.PublicKey())
	onlyPin := func(step, want string) {
		t.Helper()
		if fps := pinnedFingerprints(t, addr); len(fps) != 1 || fps[0] != want {
			t.Fatalf("%s: pins %v, want only %s", step, fps, want)
		}
	}

	d := mustRun(t, "host", "trust", "prod1")
	if d["already_pinned"] != true {
		t.Errorf("same key again: %v", d)
	}
	onlyPin("same key again", realFP)

	key.Store(&impostor)
	steps := []struct {
		name string
		args []string
		code string
	}{
		{"plain trust of a changed key", []string{"host", "trust", "prod1"}, "HOSTKEY_MISMATCH"},
		{"--reset without --yes", []string{"host", "trust", "prod1", "--reset"}, "SAFETY_SETTING"},
	}
	for _, s := range steps {
		e := wantCode(t, s.code, s.args...)
		if s.code == "HOSTKEY_MISMATCH" && (e.Exit != 4 || !containsAll(e.Message, realFP, impFP)) {
			t.Errorf("%s: %+v", s.name, e)
		}
		onlyPin(s.name, realFP)
	}

	d = mustRun(t, "host", "trust", "prod1", "--reset", "--dry-run")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("--reset --dry-run does not say it needs --yes: %v", d)
	}
	onlyPin("--reset --dry-run", realFP)

	// a server that cannot be reached keeps its pin, even with --reset
	keySSHDDown(t)
	wantCode(t, "CONNECTION_REFUSED", "host", "trust", "down", "--reset", "--yes")

	d = mustRun(t, "host", "trust", "prod1", "--reset", "--yes")
	if d["fingerprint"] != impFP || d["removed_entries"].(float64) != 1 {
		t.Errorf("--reset --yes: %v", d)
	}
	onlyPin("--reset --yes", impFP)
}

// keySSHDDown adds host "down" at a closed port, with a pinned key that
// must still be there when the test ends.
func keySSHDDown(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	mustRun(t, "host", "add", "down", "root@"+addr)
	k := trustSigner(t).PublicKey()
	if _, err := sshx.PinHostKey(addr, k, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if fps := pinnedFingerprints(t, addr); len(fps) != 1 || fps[0] != ssh.FingerprintSHA256(k) {
			t.Errorf("a failed fetch changed the pin of down: %v", fps)
		}
	})
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

// An AI agent cannot replace a pin by itself: --yes opens the approval
// window, and a person who says no keeps the old key.
func TestHostTrustResetNeedsAPersonForAgents(t *testing.T) {
	addr, key, real, impostor := trustLab(t)
	key.Store(&impostor)
	windows := asAgent(t, false, true)
	e := wantCode(t, "SAFETY_SETTING", "host", "trust", "prod1", "--reset", "--yes")
	if *windows != 1 {
		t.Errorf("approval windows: %d", *windows)
	}
	if e.Hint == "" {
		t.Error("no hint")
	}
	if fps := pinnedFingerprints(t, addr); len(fps) != 1 || fps[0] != ssh.FingerprintSHA256(real.PublicKey()) {
		t.Errorf("pins after the person said no: %v", fps)
	}
}

// A dry run says how the key would be fetched: the way komando reaches
// the server, not "directly" for every host without --via.
func TestKeyFetchPath(t *testing.T) {
	st := &store.State{Hosts: map[string]*store.Host{
		"bastion": {Name: "bastion", Address: "10.0.0.1"},
		"ssmjump": {Name: "ssmjump", Address: "i-0abc", ProxyCommand: "aws ssm start-session --target %h --document-name AWS-StartSSHSession"},
	}, Vpns: map[string]*store.Vpn{"office": {Name: "office"}}}
	cases := []struct {
		host *store.Host
		want string
	}{
		{&store.Host{Name: "web1", Address: "10.0.0.5"}, "the server directly"},
		{&store.Host{Name: "web2", Address: "10.0.0.6", Via: "bastion"}, "through jump host bastion"},
		{&store.Host{Name: "web3", Address: "10.8.0.6", Via: "office"}, "through VPN office"},
		{&store.Host{Name: "web4", Address: "10.8.0.7", Via: "office,bastion"}, "through VPN office, then jump host bastion"},
		{&store.Host{Name: "web5", Address: "i-0def", ProxyCommand: "cloudflared access ssh --hostname %h"}, "through its proxy command"},
		{&store.Host{Name: "web6", Address: "10.0.0.9", Via: "ssmjump"}, "through jump host ssmjump (by its proxy command)"},
	}
	for _, tc := range cases {
		st.Hosts[tc.host.Name] = tc.host
		if got := keyFetchPath(st, tc.host); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.host.Name, got, tc.want)
		}
	}
}
