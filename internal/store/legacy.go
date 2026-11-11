package store

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/sgnd/komando/internal/out"
)

// ReadOldState reads the inventory of a folder of an earlier komando
// (state.json, and runtime.json beside it), for `komando seal`. It only
// reads: komando never writes these files any more. A folder without
// state.json reads as empty.
func ReadOldState() (*State, error) {
	s := &State{Settings: DefaultSettings()}
	p := Path("state.json")
	b, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		// an empty file was cut short (a crash or power loss); sealing it
		// as an empty folder would drop every protected flag
		if err := json.Unmarshal(b, s); err != nil {
			return nil, out.Errf(out.ExitError, "STATE_CORRUPT",
				"the file is empty or broken, most likely cut short by a crash or power loss; ask the user to restore it from a backup (Time Machine or similar) before sealing",
				"corrupt state file %s: %v", p, err)
		}
	}
	s.init()
	// runtime.json, once there, was the only record of runtime data
	rb, err := os.ReadFile(runtimePath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var rt Runtime
	if err := json.Unmarshal(rb, &rt); err != nil {
		return nil, out.Errf(out.ExitError, "STATE_CORRUPT",
			"the file holds only running VPN sessions, logins, jobs and tunnels: move it away, then run `komando seal` again",
			"corrupt runtime file %s: %v", runtimePath(), err)
	}
	rt.init()
	s.Runtime = rt
	return s, nil
}
