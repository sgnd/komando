package sshx

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyStore keeps the server host keys komando pinned, in the sealed
// store (docs/design/sync-security.md section 16).
type hostKeyStore interface {
	// view and update run fn with the pins locked against other komando
	// processes; only update may change them. ctx bounds the wait for
	// another process's lock (the dial's context, in a connection).
	view(ctx context.Context, fn func(hostKeyTx) error) error
	update(ctx context.Context, fn func(hostKeyTx) error) error
}

// hostKeyTx reads and changes pins inside one locked step.
type hostKeyTx interface {
	// Check answers as a knownhosts callback does: nil, or a
	// *knownhosts.KeyError whose Want is empty for an unknown host and
	// holds the pinned keys for a changed one.
	Check(hostname string, remote net.Addr, key ssh.PublicKey) error
	// Pins are the keys pinned for addr (host:port) and how many pins it
	// has, keys that do not parse included.
	Pins(addr string) (keys []ssh.PublicKey, count int, err error)
	// Add pins key for addr beside its other pins.
	Add(addr string, key ssh.PublicKey) error
	// Replace makes key the only pin for addr, in one write.
	Replace(addr string, key ssh.PublicKey) error
}

// HostKeys is where this process keeps pins: the sealed store.
func HostKeys() hostKeyStore { return sealedHostKeys{} }

// WritePinsFile writes the pins of addrs (host:port) as a known_hosts file
// in dir, readable by this user only, for OpenSSH (host ssh-command on a
// sealed home), and returns its path.
func WritePinsFile(dir string, addrs []string) (string, error) {
	var lines []string
	err := HostKeys().view(context.Background(), func(t hostKeyTx) error {
		for _, a := range addrs {
			keys, _, err := t.Pins(a)
			if err != nil {
				return err
			}
			for _, k := range keys {
				lines = append(lines, knownhosts.Line([]string{knownhosts.Normalize(a)}, k))
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "known_hosts")
	return p, os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}
