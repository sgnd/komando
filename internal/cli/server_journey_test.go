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

func TestExecTimeoutNamesJobStart(t *testing.T) {
	o := execOpts{sudo: true, dir: "/srv/app", env: []string{"MODE=full"}}
	got := jobStartLine("exec", "web1", "pg_dump app | gzip > /b/app.gz", nil, o)
	want := `komando job start web1 --sudo --dir /srv/app --env MODE=full -- 'pg_dump app | gzip > /b/app.gz'`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// job start has no input, pty or --sudo-user; module commands build
	// their own scripts: no line to copy then
	for name, c := range map[string]struct {
		name  string
		stdin []byte
		o     execOpts
	}{
		"stdin":     {"exec", []byte("x"), execOpts{}},
		"pty":       {"exec", nil, execOpts{pty: true}},
		"sudo-user": {"exec", nil, execOpts{sudoUser: "app"}},
		"svc":       {"svc.restart", nil, execOpts{}},
		"script":    {"exec", nil, execOpts{display: "./deploy.sh"}},
	} {
		if got := jobStartLine(c.name, "web1", "uptime", c.stdin, c.o); got != "" {
			t.Errorf("%s: %q, want none", name, got)
		}
	}
}

func TestFsPermissionHintIsTheLineWithSudo(t *testing.T) {
	root := fsCmd()
	sub, _, err := root.Find([]string{"restore"})
	if err != nil {
		t.Fatal(err)
	}
	sub.Flags().Bool("yes", false, "the global approval flag")
	if err := sub.ParseFlags([]string{"--from", "/etc/app.conf.bak", "--yes"}); err != nil {
		t.Fatal(err)
	}
	got := sudoRetryHint(sub, []string{"web1", "/etc/app.conf"})
	// alone, fs is the root here; under komando it reads `komando fs restore ...`
	want := "retry with --sudo: `fs restore web1 /etc/app.conf --from /etc/app.conf.bak --sudo`"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if strings.Contains(got, "--yes") {
		t.Errorf("an approval flag is in the hint: %s", got)
	}
	// with --sudo already, retrying with it is no advice
	if err := sub.ParseFlags([]string{"--sudo"}); err != nil {
		t.Fatal(err)
	}
	if got := sudoRetryHint(sub, []string{"web1", "/etc/app.conf"}); strings.Contains(got, "retry with --sudo") {
		t.Errorf("already --sudo: %s", got)
	}
}
