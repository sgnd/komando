package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// Moving a VPN moves the stored passwords of the servers and conns whose
// --via goes through it (C111): an AI agent's move asks a person, as a
// change of their own --via does (SECRET_DESTINATION), and the window
// names each one.
func TestVpnMoveNamesPasswordsBehindIt(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "host", "add", "jump", "u@10.0.0.1", "--via", "lab", "--identity", writeTemp(t, "id", "k"))
	mustRun(t, "host", "add", "db1", "u@10.0.0.2", "--via", "jump", "--password-ref", "credential:db1-pass")
	mustRun(t, "conn", "add", "app-db", "postgres://a@10.0.0.3/x", "--via", "lab", "--password-ref", "credential:app-pass")
	mustRun(t, "host", "add", "keyonly", "u@10.0.0.4", "--via", "lab", "--identity", writeTemp(t, "id2", "k"))
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	e := wantCode(t, "SECRET_DESTINATION", "vpn", "socks", "edit", "lab", "--proxy-address", "203.0.113.9:1080")
	for _, w := range []string{"server db1", "conn app-db", "vpn lab"} {
		if !strings.Contains(e.Message, w) {
			t.Errorf("the stop lacks %q: %s", w, e.Message)
		}
	}
	if strings.Contains(e.Message, "keyonly") {
		t.Errorf("a key-only server sends no password: %s", e.Message)
	}
	texts := windowText(t, false)
	invRun(t, "vpn", "socks", "edit", "lab", "--proxy-address", "203.0.113.9:1080", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server db1") {
		t.Errorf("window: %q", *texts)
	}
	st, _ := store.Load()
	if st.Vpns["lab"].Address != "127.0.0.1:1080" {
		t.Fatal("a refused move was saved")
	}
	// what does not move the VPN goes on; a person's own edit is unchanged
	mustRun(t, "vpn", "socks", "edit", "lab", "--notes", "lab proxy")
	noAgent(t)
	mustRun(t, "vpn", "socks", "edit", "lab", "--proxy-address", "127.0.0.1:1081")
}

// The neighbours of a VPN move (C111): each one that changes the way a
// stored password travels asks a person; one that keeps it asks nothing.
func TestVpnMoveNeighbours(t *testing.T) {
	setup := func(t *testing.T) {
		invHome(t)
		noAgent(t)
		mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080")
		mustRun(t, "vpn", "socks", "add", "other", "--proxy-address", "127.0.0.1:1081")
		mustRun(t, "host", "add", "db1", "u@10.0.0.2", "--via", "lab", "--password-ref", "credential:db1-pass")
		setCallerEnv(t, "KOMANDO_AGENT", "1")
	}
	t.Run("another VPN put first on the way", func(t *testing.T) {
		setup(t)
		wantCode(t, "SECRET_DESTINATION", "host", "edit", "db1", "--via", "other,lab")
	})
	t.Run("a new VPN under a name the way already names", func(t *testing.T) {
		setup(t)
		noAgent(t)
		_, e := invRun(t, "host", "add", "db2", "u@10.0.0.3", "--via", "ghost", "--password-ref", "credential:db2-pass")
		setCallerEnv(t, "KOMANDO_AGENT", "1")
		if e == nil {
			wantCode(t, "SECRET_DESTINATION", "vpn", "socks", "add", "ghost", "--proxy-address", "203.0.113.9:1080")
		} else if e.Code != "VIA_NOT_FOUND" {
			t.Fatalf("a --via naming no VPN: %v", e)
		}
	})
	t.Run("the VPN removed", func(t *testing.T) {
		setup(t)
		_, e := invRun(t, "vpn", "socks", "remove", "lab")
		st, _ := store.Load()
		if _, ok := st.Vpns["lab"]; !ok {
			t.Fatalf("an agent removed a VPN with a stored password behind it: db1 via %q", st.Hosts["db1"].Via)
		}
		t.Logf("vpn rm with db1 behind it: %v", e)
	})
	t.Run("the VPN renamed", func(t *testing.T) {
		setup(t)
		mustRun(t, "rename", "lab", "lab2")
		st, _ := store.Load()
		if st.Hosts["db1"].Via != "lab2" {
			t.Fatalf("the way did not follow the rename: %q", st.Hosts["db1"].Via)
		}
	})
}
