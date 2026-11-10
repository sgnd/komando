package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/out"
)

// Runtime is what komando's background work keeps between commands: VPN
// sessions, server logins, jobs and tunnels. It lives in runtime.json, apart
// from the inventory in state.json, so a VPN marking itself used does not
// rewrite the inventory, and the coming sealed store can seal it on its own
// (docs/design/sync-security.md section 16).
type Runtime struct {
	Sessions map[string]*VpnSession `json:"vpn_sessions,omitempty"`
	Logins   map[string]*SSHLogin   `json:"ssh_logins,omitempty"`
	Jobs     map[string]*Job        `json:"jobs,omitempty"`
	Tunnels  map[string]*Tunnel     `json:"tunnels,omitempty"`

	// legacyRuntime: state.json still holds runtime data from before
	// runtime.json; the next Update moves it
	legacyRuntime bool
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

func (r *Runtime) empty() bool {
	return len(r.Sessions)+len(r.Logins)+len(r.Jobs)+len(r.Tunnels) == 0
}

// loadRuntime reads runtime.json. Once it exists it is the only record of
// runtime data: what state.json still holds from before is ignored, or an
// entry removed after the move (and before state.json was rewritten, or by
// a background process still running an older komando) would come back.
// Such a left-behind entry names a process that has ended, and the checks
// that find dead processes drop it.
func (s *State) loadRuntime() error {
	s.legacyRuntime = !s.Runtime.empty()
	b, err := os.ReadFile(runtimePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rt Runtime
	if err := json.Unmarshal(b, &rt); err != nil {
		// only live sessions are lost: they are found again or made again
		return out.Errf(out.ExitError, "STATE_CORRUPT",
			"the file holds only running VPN sessions, logins, jobs and tunnels, no servers or settings: move it away, then connect again",
			"corrupt runtime file %s: %v", runtimePath(), err)
	}
	rt.legacyRuntime = s.legacyRuntime
	rt.init()
	s.Runtime = rt
	return nil
}

func (s *State) saveRuntime() error {
	b, err := json.MarshalIndent(&s.Runtime, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(runtimePath(), b, 0o600)
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
	if s, err := Load(); !DryRun && err == nil && s.legacyRuntime {
		// state.json still holds runtime data: move it with both locks, or
		// an entry removed here would come back from state.json
		return Update(fn)
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
