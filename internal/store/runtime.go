package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealrow"
)

// Runtime is what komando's background work keeps between commands: VPN
// sessions, server logins, jobs and tunnels. It lives in runtime.json, apart
// from the inventory in store.db, so a VPN marking itself used does not
// rewrite the inventory, and the coming sealed store can seal it on its own
// (docs/design/sync-security.md section 16).
type Runtime struct {
	Sessions map[string]*VpnSession `json:"vpn_sessions,omitempty"`
	Logins   map[string]*SSHLogin   `json:"ssh_logins,omitempty"`
	Jobs     map[string]*Job        `json:"jobs,omitempty"`
	Tunnels  map[string]*Tunnel     `json:"tunnels,omitempty"`
}

const runtimeLock = ".runtime.lock"

func runtimePath() string { return Path("runtime.json") }

func (r *Runtime) init() {
	if r.Sessions == nil {
		r.Sessions = map[string]*VpnSession{}
	}
	if r.Logins == nil {
		r.Logins = map[string]*SSHLogin{}
	}
	if r.Jobs == nil {
		r.Jobs = map[string]*Job{}
	}
	if r.Tunnels == nil {
		r.Tunnels = map[string]*Tunnel{}
	}
}

// loadRuntime reads runtime.json, sealed with the store's key.
func (s *State) loadRuntime() error {
	b, err := os.ReadFile(runtimePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if b, err = openRuntime(b); err != nil {
		if errors.Is(err, sealrow.ErrOpen) {
			return out.Errf(out.ExitError, "STATE_CORRUPT",
				"the file holds only running VPN sessions, logins, jobs and tunnels: move it away, then connect again (a VPN started before the store's key changed is ended by `komando vpn down`)",
				"%s does not open with the store's key", runtimePath())
		}
		return err
	}
	var rt Runtime
	if err := json.Unmarshal(b, &rt); err != nil {
		// only live sessions are lost: they are found again or made again
		return out.Errf(out.ExitError, "STATE_CORRUPT",
			"the file holds only running VPN sessions, logins, jobs and tunnels, no servers or settings: move it away, then connect again",
			"corrupt runtime file %s: %v", runtimePath(), err)
	}
	rt.init()
	s.Runtime = rt
	return nil
}

func (s *State) saveRuntime() error {
	b, err := json.MarshalIndent(&s.Runtime, "", "  ")
	if err != nil {
		return err
	}
	if b, err = sealRuntime(b); err != nil {
		return err
	}
	if err := WriteFileAtomic(runtimePath(), b, 0o600); err != nil {
		return err
	}
	return s.Runtime.writeRuntimePIDs()
}

// ReadRuntime reads runtime.json alone, sealed or not, for a caller that
// needs only the running sessions and tunnels (the shell prompt).
func ReadRuntime() (*Runtime, error) {
	b, err := os.ReadFile(runtimePath())
	if err != nil {
		return nil, err
	}
	if b, err = openRuntime(b); err != nil {
		return nil, err
	}
	var rt Runtime
	if err := json.Unmarshal(b, &rt); err != nil {
		return nil, err
	}
	rt.init()
	return &rt, nil
}

// ErrRuntimeOnly: fn of UpdateRuntime changed the inventory, which
// UpdateRuntime does not save. A bug in the caller.
var ErrRuntimeOnly = errors.New("store: UpdateRuntime changed more than runtime data; use Update")

// UpdateRuntime is Update for a change to runtime data only (Sessions,
// Logins, Jobs, Tunnels). It takes the runtime lock and not the inventory
// lock, and saves runtime.json only, so background processes do not wait
// for, or rewrite, the inventory. fn sees the whole state; a change to
// anything else stops it with ErrRuntimeOnly and nothing is saved.
//
// Never call Update or UpdateRuntime from inside fn.
func UpdateRuntime(fn func(s *State) error) error {
	if !DryRun {
		if err := ensureHome(); err != nil {
			return err
		}
	}
	if !DryRun {
		unlock, err := Lock(runtimeLock)
		if err != nil {
			return err
		}
		defer unlock()
	}
	s, err := Load()
	if err != nil {
		return err
	}
	inv := func() ([]byte, error) {
		c := *s
		c.Runtime = Runtime{}
		return json.Marshal(&c)
	}
	before, err := inv()
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	after, err := inv()
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return ErrRuntimeOnly
	}
	if DryRun {
		return nil
	}
	return s.saveRuntime()
}
