package cli

import (
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// O7: db dump/restore --run-on HOST sends the conn's password to HOST. For
// an AI agent a server other than the conn's own --via server needs a
// person's yes (SECRET_DESTINATION); the conn's own server does not.
func TestRunOnOtherServerNeedsYesForPassword(t *testing.T) {
	invHome(t)
	st := &store.State{Hosts: map[string]*store.Host{
		"db1":   {Name: "db1", Address: "10.0.0.1"},
		"other": {Name: "other", Address: "10.0.0.2"},
	}}
	via := &store.Conn{Name: "pg", Via: "db1", PasswordRef: "secret:pg"}
	direct := &store.Conn{Name: "pg2", PasswordRef: "secret:pg"}
	nopw := &store.Conn{Name: "pg3"}

	asAgent(t, false, false)
	if h, err := toolHost(tcl, st, via, "db1"); err != nil || h == nil || h.Name != "db1" {
		t.Fatalf("own --via server: %v %v", h, err)
	}
	for _, c := range []*store.Conn{via, direct} {
		_, err := toolHost(tcl, st, c, "other")
		if e := toErr(err); err == nil || e.Code != "SECRET_DESTINATION" {
			t.Errorf("%s --run-on other: %v", c.Name, err)
		}
	}
	if _, err := toolHost(tcl, st, nopw, "other"); err != nil {
		t.Errorf("no password: %v", err)
	}
	noAgent(t)
	resetApproval()
	if _, err := toolHost(tcl, st, direct, "other"); err != nil {
		t.Errorf("a person: %v", err)
	}
}
