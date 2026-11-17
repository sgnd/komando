package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// A server whose pinned host key is this computer's own SSH host key is
// this computer under another name or address: the gate treats it as
// here. Another key, or no pin, is judged by the address alone.
func TestGateSeesThisComputerByHostKey(t *testing.T) {
	invHome(t)
	pub := func() ssh.PublicKey {
		k, _, _ := ed25519.GenerateKey(rand.Reader)
		p, _ := ssh.NewPublicKey(k)
		return p
	}
	own, other := pub(), pub()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), ssh.MarshalAuthorizedKey(own), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := sshdHostKeys
	sshdHostKeys = filepath.Join(dir, "ssh_host_*_key.pub")
	t.Cleanup(func() { sshdHostKeys = saved })

	me := &store.Host{Name: "lanbox", Address: "203.0.113.7", Port: 2222}
	them := &store.Host{Name: "web1", Address: "203.0.113.8"}
	if _, err := sshx.PinHostKey("203.0.113.7:2222", own, false); err != nil {
		t.Fatal(err)
	}
	if _, err := sshx.PinHostKey("203.0.113.8:22", other, false); err != nil {
		t.Fatal(err)
	}
	if !gateSameHostKey(me) {
		t.Error("a server with this computer's host key is not seen as here")
	}
	if gateSameHostKey(them) || gateSameHostKey(&store.Host{Name: "new", Address: "203.0.113.9"}) {
		t.Error("another server, or one never reached, is taken for this computer")
	}
}

// An address of this computer's own network interfaces (its LAN address)
// is this computer.
func TestGateSeesOwnAddresses(t *testing.T) {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			if !gateLocalAddr(n.IP.String()) || !gateLocalAddr(net.JoinHostPort(n.IP.String(), "22")) {
				t.Errorf("%s is this computer's own address", n.IP)
			}
			break
		}
	}
	if gateLocalAddr("203.0.113.10") {
		t.Error("a documentation address is not this computer")
	}
}
