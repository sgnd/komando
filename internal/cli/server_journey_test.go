package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// The next step of a server journey is a command to copy, with the real
// names in it: exec that timed out → job start, job start → job wait with
// every ID, a refused fs edit → the same line with --sudo.

func TestJobStartNextHasTheIDs(t *testing.T) {
	one := jobStarted{Jobs: []started{{ID: "j1", Host: "web1", OK: true}}, Summary: fleetSummary{Total: 1, OK: 1}}.withNext()
	if !strings.Contains(one.Next, "komando job wait j1") || strings.Contains(one.Next, "<id>") {
		t.Errorf("one job: %q", one.Next)
	}
	many := jobStarted{Jobs: []started{{ID: "j1", Host: "web1", OK: true}, {Host: "web2", Error: &out.Error{Code: "AUTH_FAILED"}}, {ID: "j3", Host: "web3", OK: true}},
		Summary: fleetSummary{Total: 3, OK: 2, Failed: 1}}.withNext()
	if !strings.Contains(many.Next, "komando job wait j1 j3") {
		t.Errorf("several jobs: %q", many.Next)
	}
	if txt := many.Text(); !strings.Contains(txt, "komando job wait j1 j3") {
		t.Errorf("several jobs, text:\n%s", txt)
	}
	if h := many.fleetHint(); strings.Contains(h, "data.results") {
		t.Errorf("job start hint points at data.results: %q", h)
	}
}

func TestJobWaitHintWaitsAgain(t *testing.T) {
	d := jobWaited{Jobs: []waitRow{
		{ID: "j1", Error: &out.Error{Code: "WAIT_TIMEOUT"}},
		{ID: "j2", OK: true},
		{ID: "j3", Error: &out.Error{Code: "JOB_FAILED"}},
		{ID: "j4", Error: &out.Error{Code: "WAIT_TIMEOUT"}},
	}}
	h := d.fleetHint()
	if !strings.Contains(h, "`komando job wait j1 j4`") || strings.Contains(h, "data.results") || strings.Contains(h, "job start") {
		t.Errorf("hint: %q", h)
	}
}
