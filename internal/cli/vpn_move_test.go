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
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "host", "add", "jump", "u@10.0.0.1", "--via", "lab", "--identity", writeTemp(t, "id", "k"))
	mustRun(t, "host", "add", "db1", "u@10.0.0.2", "--via", "jump", "--password-ref", "secret:db1-pass")
	mustRun(t, "conn", "add", "app-db", "postgres://a@10.0.0.3/x", "--via", "lab", "--password-ref", "secret:app-pass")
	mustRun(t, "host", "add", "keyonly", "u@10.0.0.4", "--via", "lab", "--identity", writeTemp(t, "id2", "k"))
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	e := wantCode(t, "SECRET_DESTINATION", "vpn", "edit", "lab", "--proxy-address", "203.0.113.9:1080")
	for _, w := range []string{"server db1", "conn app-db", "vpn lab"} {
		if !strings.Contains(e.Message, w) {
			t.Errorf("the stop lacks %q: %s", w, e.Message)
		}
	}
	if strings.Contains(e.Message, "keyonly") {
		t.Errorf("a key-only server sends no password: %s", e.Message)
	}
	texts := windowText(t, false)
	invRun(t, "vpn", "edit", "lab", "--proxy-address", "203.0.113.9:1080", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "server db1") {
		t.Errorf("window: %q", *texts)
	}
	st, _ := store.Load()
	if st.Vpns["lab"].Address != "127.0.0.1:1080" {
		t.Fatal("a refused move was saved")
	}
	// what does not move the VPN goes on; a person's own edit is unchanged
	mustRun(t, "vpn", "edit", "lab", "--notes", "lab proxy")
	noAgent(t)
	mustRun(t, "vpn", "edit", "lab", "--proxy-address", "127.0.0.1:1081")
}
