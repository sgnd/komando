package sshx

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/store"
)

// hostKeyStore keeps the server host keys komando pinned. Today it is the
// known_hosts file; the sealed local store (docs/design/sync-security.md
// section 16) takes its place behind the same methods.
type hostKeyStore interface {
	// view and update run fn with the pins locked against other komando
	// processes; only update may change them
	view(fn func(hostKeyTx) error) error
	update(fn func(hostKeyTx) error) error
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

// HostKeys is where this process keeps pins: the sealed store on a sealed
// home, known_hosts otherwise.
func HostKeys() hostKeyStore {
	if store.Sealed() {
		return sealedHostKeys{}
	}
	return fileHostKeys{}
}

// fileHostKeys is known_hosts in komando's folder. A lock file keeps
// komando processes from writing it at the same time; khMu does the same
// for goroutines of one process, as the lock file is per process.
type fileHostKeys struct{}

var khMu sync.Mutex

const khLock = ".known_hosts.lock"

func (f fileHostKeys) view(fn func(hostKeyTx) error) error   { return f.run(fn) }
func (f fileHostKeys) update(fn func(hostKeyTx) error) error { return f.run(fn) }

func (fileHostKeys) run(fn func(hostKeyTx) error) error {
	khMu.Lock()
	defer khMu.Unlock()
	unlock, err := store.Lock(khLock)
	if err != nil {
		return err
	}
	defer unlock()
	p := KnownHostsPath()
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			return err
		}
	}
	return fn(fileTx{p})
}

type fileTx struct{ path string }

func (t fileTx) Check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cb, err := knownhosts.New(t.path)
	if err != nil {
		return err
	}
	return cb(hostname, remote, key)
}

func (t fileTx) Pins(addr string) ([]ssh.PublicKey, int, error) {
	pins, n, _, err := knownHostsLines(t.path, addr)
	return pins, n, err
}

func (t fileTx) Add(addr string, key ssh.PublicKey) error {
	f, err := os.OpenFile(t.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(addr)}, key))
	return err
}

func (t fileTx) Replace(addr string, key ssh.PublicKey) error {
	_, _, keep, err := knownHostsLines(t.path, addr)
	if err != nil {
		return err
	}
	keep = append(keep, []byte(knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)))
	return store.WriteFileAtomic(t.path, append(bytes.Join(keep, []byte("\n")), '\n'), 0o600)
}

// knownHostsLines splits known_hosts into the lines that pin addr (host:port
// normalised) and the rest, and returns the keys of the first kind.
func knownHostsLines(p, addr string) (pins []ssh.PublicKey, matched int, keep [][]byte, err error) {
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil, nil
		}
		return nil, 0, nil, err
	}
	norm := knownhosts.Normalize(addr)
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) > 0 && hostsFieldMatches(f[0], norm) {
			matched++
			if _, _, k, _, _, err := ssh.ParseKnownHosts(line); err == nil {
				pins = append(pins, k)
			}
			continue
		}
		if len(line) > 0 {
			keep = append(keep, line)
		}
	}
	return pins, matched, keep, nil
}

func hostsFieldMatches(field, norm string) bool {
	for _, h := range strings.Split(field, ",") {
		if h == norm {
			return true
		}
	}
	return false
}

// WritePinsFile writes the pins of addrs (host:port) as a known_hosts file
// in dir, readable by this user only, for OpenSSH (host ssh-command on a
// sealed home), and returns its path.
func WritePinsFile(dir string, addrs []string) (string, error) {
	var lines []string
	err := HostKeys().view(func(t hostKeyTx) error {
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
