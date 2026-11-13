package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/sealrow"
)

// runtime.json is sealed too: it holds the SOCKS logins of running VPNs and the tokens of
// kept server logins. It is sealed with the store's row key, bound to its
// own ID and type, so it cannot be swapped with a store record. A plain
// runtime.json was put there by something other than komando, and is read
// as empty. Trusted, it could point a server's
// held login at a socket of its own, which would then see every command,
// password and file sent to that server.

var runtimeMagic = []byte("komando-runtime-sealed-1\n")

var runtimeRow = sealrow.Row{ID: "runtime", Type: "runtime", Version: 1}

var (
	rtKeyMu   sync.Mutex
	rtKeyHome string
	rtKey     *sealrow.Key
)

// runtimeKey is the row key of this home's store, made once per process.
func runtimeKey() (*sealrow.Key, error) {
	rtKeyMu.Lock()
	defer rtKeyMu.Unlock()
	if rtKey != nil && rtKeyHome == Home() {
		return rtKey, nil
	}
	m, err := MasterKey()
	if err != nil {
		return nil, err
	}
	defer clear(m)
	k, err := sealrow.NewKey(m)
	if err != nil {
		return nil, err
	}
	rtKey, rtKeyHome = k, Home()
	return k, nil
}

func sealRuntime(plain []byte) ([]byte, error) {
	k, err := runtimeKey()
	if errors.Is(err, ErrNoStore) {
		// no store yet (a VPN brought up before any change): make it, so
		// the runtime data is never written plain
		if _, err = DB(true); err == nil {
			k, err = runtimeKey()
		}
	}
	if err != nil {
		return nil, err
	}
	sealed, err := k.Seal(runtimeRow, plain)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, runtimeMagic...), sealed...), nil
}

func openRuntime(b []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(b, runtimeMagic)
	if !ok {
		// never trusted: only running sessions are lost, found or made again
		return []byte("{}"), nil
	}
	k, err := runtimeKey()
	if err != nil {
		return nil, err
	}
	plain, err := k.Open(runtimeRow, rest)
	if errors.Is(err, sealrow.ErrOpen) {
		// the store's key changed since this process read it (a long
		// running VPN while `secret passphrase` ran): read it again
		rtKeyMu.Lock()
		rtKey = nil
		rtKeyMu.Unlock()
		if k, err = runtimeKey(); err != nil {
			return nil, err
		}
		plain, err = k.Open(runtimeRow, rest)
	}
	return plain, err
}

// RuntimePIDs is what the shell prompt may know of a sealed home's
// runtime data without its key: the processes of running VPNs (with when
// each was last used) and tunnels. No names, logins or tokens.
type RuntimePIDs struct {
	Vpns    []VpnPID `json:"vpns,omitempty"`
	Tunnels []int    `json:"tunnels,omitempty"`
}

// VpnPID is one running VPN in RuntimePIDs.
type VpnPID struct {
	PID      int       `json:"pid"`
	LastUsed time.Time `json:"last_used"`
}

func runtimePIDsPath() string { return Path("runtime.pids") }

// writeRuntimePIDs keeps runtime.pids beside a sealed runtime.json.
func (r *Runtime) writeRuntimePIDs() error {
	var p RuntimePIDs
	for _, s := range r.Sessions {
		if s != nil {
			p.Vpns = append(p.Vpns, VpnPID{PID: s.PID, LastUsed: s.LastUsed})
		}
	}
	for _, t := range r.Tunnels {
		if t != nil {
			p.Tunnels = append(p.Tunnels, t.PID)
		}
	}
	b, err := json.Marshal(&p)
	if err != nil {
		return err
	}
	return WriteFileAtomic(runtimePIDsPath(), b, 0o600)
}

// ReadRuntimePIDs reads runtime.pids: on a sealed home, the only runtime
// data that opens without the store's key.
func ReadRuntimePIDs() (*RuntimePIDs, error) {
	b, err := os.ReadFile(runtimePIDsPath())
	if err != nil {
		return nil, err
	}
	var p RuntimePIDs
	return &p, json.Unmarshal(b, &p)
}
