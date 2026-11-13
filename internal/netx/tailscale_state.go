package netx

import (
	"os"
	"sync"

	"tailscale.com/ipn"

	"github.com/sgnd/komando/internal/store"
)

// sealedTSState keeps a Tailscale node's state (its machine and node
// private keys among it) sealed in komando's store, not in tsnet's plain
// tailscaled.state file: a stolen laptop or a copied folder would give
// the node's place on the tailnet, and every server it reaches.
type sealedTSState struct {
	id string // the VPN's record ID: the same after a rename
	mu sync.Mutex
}

func tsStateID(v *store.Vpn) string {
	if v.Rec.ID != "" {
		return v.Rec.ID
	}
	return "name:" + v.Name
}

func (s *sealedTSState) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok, err := store.VPNState(s.id, string(id))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return b, nil
}

func (s *sealedTSState) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bs == nil {
		return store.SetVPNState(s.id, map[string][]byte{string(id): nil})
	}
	return store.SetVPNState(s.id, map[string][]byte{string(id): append([]byte{}, bs...)})
}

// ForgetTailscale removes a VPN's node state and folder (vpn rm).
func ForgetTailscale(v *store.Vpn) error {
	err := store.DeleteVPNState(tsStateID(v))
	if rerr := os.RemoveAll(TailscaleDir(v)); err == nil {
		err = rerr
	}
	return err
}
