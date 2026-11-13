package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/sgnd/komando/internal/sealdb"
)

// The state of a VPN client that runs inside komando (a Tailscale node's
// machine and node keys) is kept sealed in the store, one record per VPN,
// never in a plain file beside it.

const vpnStateType = "vpnstate"

type vpnState struct {
	Vpn    string            `json:"vpn"`
	Values map[string][]byte `json:"values"`
}

// findVPNState returns the record of vpn's state, or "" and an empty one.
func findVPNState(tx *sealdb.Tx, vpn string) (string, vpnState, error) {
	rows, err := tx.List(vpnStateType)
	if err != nil {
		return "", vpnState{}, err
	}
	for _, r := range rows {
		var s vpnState
		if err := json.Unmarshal(r.Data, &s); err != nil {
			return "", vpnState{}, err
		}
		if s.Vpn == vpn {
			return r.ID, s, nil
		}
	}
	return "", vpnState{Vpn: vpn, Values: map[string][]byte{}}, nil
}

// VPNState returns the value key of vpn's state, and whether there is one.
func VPNState(vpn, key string) ([]byte, bool, error) {
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var v []byte
	var ok bool
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		_, s, err := findVPNState(tx, vpn)
		v, ok = s.Values[key]
		return err
	})
	return v, ok, err
}

// SetVPNState keeps values in vpn's state; a nil value removes its key.
func SetVPNState(vpn string, values map[string][]byte) error {
	d, err := DB(true)
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		id, s, err := findVPNState(tx, vpn)
		if err != nil {
			return err
		}
		if s.Values == nil {
			s.Values = map[string][]byte{}
		}
		for k, v := range values {
			if v == nil {
				delete(s.Values, k)
			} else {
				s.Values[k] = v
			}
		}
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		_, err = tx.Put(vpnStateType, id, b)
		return err
	})
}

// DeleteVPNState forgets vpn's state (vpn rm).
func DeleteVPNState(vpn string) error {
	d, err := DB(false)
	if errors.Is(err, ErrNoStore) {
		return nil
	}
	if err != nil {
		return err
	}
	return d.Update(context.Background(), func(tx *sealdb.Tx) error {
		id, _, err := findVPNState(tx, vpn)
		if err != nil || id == "" {
			return err
		}
		return tx.Delete(id)
	})
}
