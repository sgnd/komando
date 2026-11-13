package netx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"

	"github.com/sgnd/komando/internal/store"
)

// tsHome is a throwaway komando home with a stand-in store key.
func tsHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(store.Close) // before the folder goes: Windows cannot remove an open file
	t.Setenv("KOMANDO_KEYCHAIN", "off")
	old := store.KeySource
	store.KeySource = func(map[string]string, bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "test"}, nil
	}
	t.Cleanup(func() { store.KeySource = old })
}

// A Tailscale node's keys are sealed in the store, nothing in the folder
// holds them in the clear, and vpn rm forgets them.
func TestTailscaleStateSealed(t *testing.T) {
	tsHome(t)
	v := &store.Vpn{Name: "tnet", Kind: "tailscale", Rec: store.Rec{ID: "abc"}}
	if err := os.MkdirAll(TailscaleDir(v), 0o700); err != nil {
		t.Fatal(err)
	}
	priv := []byte(`{"PrivateMachineKey":"privkey:0011223344556677"}`)
	s := &sealedTSState{id: tsStateID(v)}
	if err := s.WriteState("_machinekey", []byte("privkey:0011223344556677")); err != nil {
		t.Fatal(err)
	}
	if b, err := s.ReadState("_machinekey"); err != nil || string(b) != "privkey:0011223344556677" {
		t.Fatalf("read: %q %v", b, err)
	}
	if err := s.WriteState("_profiles", priv); err != nil {
		t.Fatal(err)
	}
	if b, err := s.ReadState("_profiles"); err != nil || !bytes.Equal(b, priv) {
		t.Fatalf("round trip: %q %v", b, err)
	}
	if _, err := s.ReadState("nothing"); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("missing key: %v", err)
	}
	// nothing readable anywhere in the folder
	_ = filepath.WalkDir(store.Home(), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("0011223344556677")) {
				t.Errorf("%s holds the node key in the clear", p)
			}
		}
		return nil
	})
	// tsnet gets the sealed store, so it never writes tailscaled.state
	srv, err := newTailscale(v)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.Store.(*sealedTSState); !ok {
		t.Fatalf("tsnet keeps its state in %T", srv.Store)
	}
	if err := ForgetTailscale(v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadState("_machinekey"); !errors.Is(err, ipn.ErrStateNotExist) {
		t.Fatalf("vpn rm kept the node key: %v", err)
	}
	if _, err := os.Stat(TailscaleDir(v)); !os.IsNotExist(err) {
		t.Fatal("vpn rm kept the folder")
	}
}
