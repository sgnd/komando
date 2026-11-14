package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
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
	if trustRow0(d)["fingerprint"] != ssh.FingerprintSHA256(real.PublicKey()) {
		t.Fatalf("first pin: %v", d)
	}
	return addr, key, real, impostor
}

// trustRow0 is the first server's row of a host trust answer: one server
// or many, it is data.results.
func trustRow0(d map[string]any) map[string]any {
	rows, _ := d["results"].([]any)
	if len(rows) == 0 {
		return nil
	}
	r, _ := rows[0].(map[string]any)
	return r
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
	if trustRow0(d)["already_pinned"] != true {
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
		{"--reset from a script", []string{"host", "trust", "prod1", "--reset"}, "NEEDS_PERSON"},
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
		t.Errorf("--reset --dry-run does not say it needs a person: %v", d)
	}
	onlyPin("--reset --dry-run", realFP)

	// a server that cannot be reached keeps its pin, even with --reset
	keySSHDDown(t)
	wantCode(t, "NEEDS_PERSON", "host", "trust", "down", "--reset") // a script: stopped before it connects
	personTypes(t, "y")
	wantCode(t, "CONNECTION_REFUSED", "host", "trust", "down", "--reset")

	personTypes(t, "y") // a person at the terminal replaces it (OD-9)
	d = mustRun(t, "host", "trust", "prod1", "--reset")
	if r := trustRow0(d); r["fingerprint"] != impFP || r["removed_entries"].(float64) != 1 {
		t.Errorf("--reset by a person: %v", d)
	}
	onlyPin("--reset by a person", impFP)
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

// An AI agent never replaces a pin (OD-9, AGENTS rule 8): it gets
// NEEDS_PERSON, which no flag lifts and which opens no window, and the
// hint names the command a person runs. The old key stays.
func TestHostTrustResetNeedsAPersonForAgents(t *testing.T) {
	addr, key, real, impostor := trustLab(t)
	key.Store(&impostor)
	windows := asAgent(t, true, true)
	e := wantCode(t, "NEEDS_PERSON", "host", "trust", "prod1", "--reset")
	if *windows != 0 {
		t.Errorf("approval windows: %d", *windows)
	}
	if !e.Final || !strings.Contains(e.Hint, "komando host trust prod1 --reset") || out.ApprovalFlag(e) != "" {
		t.Errorf("no flag lifts it, and the hint names the person's command: %+v", e)
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

// trustGroup adds n servers in group lab, each at its own SSH server whose
// key the test can swap, and returns their addresses and key holders.
func trustGroup(t *testing.T, n int) ([]string, []*atomic.Pointer[ssh.Signer]) {
	t.Helper()
	invHome(t)
	var addrs []string
	var keys []*atomic.Pointer[ssh.Signer]
	for i := range n {
		k := new(atomic.Pointer[ssh.Signer])
		s := trustSigner(t)
		k.Store(&s)
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(keySSHD(t, k)))
		mustRun(t, "host", "add", "node"+strconv.Itoa(i+1), "root@"+addr, "-g", "lab")
		addrs, keys = append(addrs, addr), append(keys, k)
	}
	return addrs, keys
}

func trustResults(t *testing.T, d map[string]any) map[string]map[string]any {
	t.Helper()
	res := map[string]map[string]any{}
	for _, r := range d["results"].([]any) {
		m := r.(map[string]any)
		res[m["host"].(string)] = m
	}
	return res
}

// After a rebuild of a group (same addresses, new keys), `host trust
// @group` refuses the changed keys and pins nothing twice; `--reset` then
// replaces them all after one window that names every changed server.
func TestHostTrustGroup(t *testing.T) {
	addrs, keys := trustGroup(t, 3)
	d := mustRun(t, "host", "trust", "@lab")
	if s := d["summary"].(map[string]any); s["ok"].(float64) != 3 {
		t.Fatalf("first pin: %v", d)
	}
	// node1 and node2 are rebuilt; node3 is not
	var newFP []string
	for _, i := range []int{0, 1} {
		s := trustSigner(t)
		keys[i].Store(&s)
		newFP = append(newFP, ssh.FingerprintSHA256(s.PublicKey()))
	}
	old1 := pinnedFingerprints(t, addrs[0])[0]
	d, e := invRun(t, "host", "trust", "@lab")
	if e == nil || e.Code != "PARTIAL_FAILURE" {
		t.Fatalf("plain trust after the rebuild: %+v", e)
	}
	r := trustResults(t, d)
	if r["node1"]["error"].(map[string]any)["code"] != "HOSTKEY_MISMATCH" || r["node3"]["already_pinned"] != true {
		t.Errorf("results: %v", r)
	}
	if fps := pinnedFingerprints(t, addrs[0]); len(fps) != 1 || fps[0] != old1 {
		t.Errorf("node1 pins after a refused trust: %v", fps)
	}

	// a person at the terminal: one question for the whole group, naming
	// each server whose key changes with its new key
	personTypes(t, "y")
	screen, err := os.CreateTemp(t.TempDir(), "screen")
	if err != nil {
		t.Fatal(err)
	}
	// closed before t.TempDir's cleanup: Windows cannot remove an open file
	savedStderr := tcl.out.Err
	t.Cleanup(func() { tcl.out.Err = savedStderr; _ = screen.Close() })
	tcl.out.Err = screen
	d = mustRun(t, "host", "trust", "@lab", "--reset")
	shown, _ := os.ReadFile(screen.Name())
	if text := string(shown); strings.Count(text, "[y/N]") != 1 ||
		!containsAll(text, "2 servers", "node1 "+shortFP(newFP[0]), "node2 "+shortFP(newFP[1])) || strings.Contains(text, "node3 ") {
		t.Errorf("the question: %q", text)
	}
	r = trustResults(t, d)
	if r["node1"]["fingerprint"] != newFP[0] || r["node1"]["old_fingerprints"].([]any)[0] != old1 {
		t.Errorf("node1: %v", r["node1"])
	}
	for i, want := range newFP {
		if fps := pinnedFingerprints(t, addrs[i]); len(fps) != 1 || fps[0] != want {
			t.Errorf("node%d pins: %v", i+1, fps)
		}
	}
}

// An agent is stopped and a person who says no keeps every old key; a dry
// run fetches nothing and says what --reset would need.
func TestHostTrustGroupDenied(t *testing.T) {
	addrs, keys := trustGroup(t, 2)
	mustRun(t, "host", "trust", "@lab")
	before := [][]string{pinnedFingerprints(t, addrs[0]), pinnedFingerprints(t, addrs[1])}
	for _, k := range keys {
		s := trustSigner(t)
		k.Store(&s)
	}
	d := mustRun(t, "host", "trust", "@lab", "--reset", "--dry-run")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil || len(d["results"].([]any)) != 2 {
		t.Errorf("dry run: %v", d)
	}
	asAgent(t, true, true)
	wantCode(t, "NEEDS_PERSON", "host", "trust", "@lab", "--reset")
	personTypes(t, "n")
	if e := wantCode(t, "DECLINED", "host", "trust", "@lab", "--reset"); e.Exit != out.ExitPolicy {
		t.Errorf("a person's no: %+v", e)
	}
	for i, a := range addrs {
		if fps := pinnedFingerprints(t, a); len(fps) != 1 || fps[0] != before[i][0] {
			t.Errorf("node%d pins after a no: %v", i+1, fps)
		}
	}
}

// host rm keeps a server's pinned key and says so: rm plus add must not get
// a rebuilt (or impostor) server past HOSTKEY_MISMATCH without a person.
func TestHostRmKeepsThePin(t *testing.T) {
	addrs, keys := trustGroup(t, 2)
	mustRun(t, "host", "trust", "@lab")
	mustRun(t, "host", "add", "alias1", "root@"+addrs[0]) // same address as node1

	d := mustRun(t, "host", "rm", "node1", "node2")
	if kept := d["host_keys_kept"].([]any); len(kept) != 1 || kept[0] != "node2" || !strings.Contains(d["note"].(string), "host trust NAME --reset") {
		t.Errorf("rm: %v (node1's address is still used by alias1)", d)
	}
	s := trustSigner(t)
	keys[1].Store(&s)
	mustRun(t, "host", "add", "node2", "root@"+addrs[1])
	wantCode(t, "HOSTKEY_MISMATCH", "host", "trust", "node2")
	if d := mustRun(t, "host", "rm", "alias1", "--dry-run"); d["host_keys_kept"] == nil {
		t.Errorf("dry run does not say the key stays: %v", d)
	}
}
