package cli

import (
	"crypto/tls"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// devopsHome is a komando home with web1 (logs in as deploy) and the
// Windows server win1; nothing is reached, every run is checked offline.
func devopsHome(t *testing.T) {
	t.Helper()
	invHome(t)
	t.Setenv("KOMANDO_NO_DIALOG", "1")
	mustRun(t, "host", "add", "web1", "deploy@10.255.255.1")
	mustRun(t, "host", "add", "web2", "ops@10.255.255.2")
	if err := store.Update(func(st *store.State) error {
		st.Hosts["win1"] = &store.Host{Name: "win1", Address: "10.255.255.3", User: "Administrator", OS: store.OSWindows}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func blockedBy(d map[string]any) string {
	b, _ := json.Marshal(d["would_be_blocked"])
	if string(b) == "null" {
		return ""
	}
	return string(b)
}

func TestSvcStopSSHIsBlocked(t *testing.T) {
	devopsHome(t)
	for _, args := range [][]string{
		{"svc", "stop", "web1", "ssh"},
		{"svc", "stop", "web1", "ssh.service"},
		{"svc", "stop", "web1", "nginx", "ssh.socket"},
		{"svc", "disable", "web1", "ssh", "--now"},
		{"svc", "disable", "web1", "sshd"},
	} {
		d := mustRun(t, append(args, "--dry-run")...)
		if b := blockedBy(d); !strings.Contains(b, "sshd-stop") {
			t.Errorf("%v: want the sshd-stop rule, got %s", args, b)
		}
	}
	if b := blockedBy(mustRun(t, "svc", "restart", "web1", "ssh", "--dry-run")); b != "" {
		t.Errorf("a restart keeps SSH up: %s", b)
	}
	wantCode(t, "POLICY_BLOCKED", "svc", "stop", "web1", "ssh")
}

func TestRebootRefusesWindowsFirst(t *testing.T) {
	devopsHome(t)
	for _, args := range [][]string{{"reboot", "win1", "--dry-run"}, {"reboot", "all", "--dry-run"}, {"reboot", "all"}} {
		if e := wantCode(t, "NOT_SUPPORTED", args...); !strings.Contains(e.Message, "reboot") {
			t.Errorf("%v: %s", args, e.Message)
		}
	}
}

func TestDryRunOnWindowsShowsWhatRuns(t *testing.T) {
	devopsHome(t)
	d := mustRun(t, "svc", "list", "win1", "--dry-run")
	plan := d["would_run"].([]any)[0].(map[string]any)
	if cmd := plan["remote_command"].(string); strings.Contains(cmd, "systemctl") {
		t.Errorf("svc list on Windows shows the sh script: %s", cmd)
	}
	d = mustRun(t, "facts", "win1", "--dry-run")
	if cmd := d["would_run"].(string); strings.Contains(cmd, "uname") {
		t.Errorf("facts on Windows shows the sh script: %.80s", cmd)
	}
	d = mustRun(t, "facts", "web1,win1", "--dry-run")
	if !strings.Contains(d["would_run"].(string), "uname") || d["would_run_on_windows"] == nil {
		t.Errorf("mixed facts dry run: %v", d)
	}
	wantCode(t, "NOT_SUPPORTED", "cert", "check", "win1", "--dry-run")
}

func TestDockerLogsSudo(t *testing.T) {
	devopsHome(t)
	for _, args := range [][]string{
		{"docker", "logs", "web1", "api", "--sudo"},
		{"docker", "--sudo", "logs", "web1", "api"},
	} {
		d := mustRun(t, append(args, "--dry-run")...)
		if plan := d["would_run"].([]any)[0].(map[string]any); plan["sudo"] != true {
			t.Errorf("%v: sudo %v", args, plan["sudo"])
		}
	}
}

func TestNetHTTPChecksURLAndExpect(t *testing.T) {
	devopsHome(t)
	for _, args := range [][]string{
		{"net", "http", "web2", "--", "-K/tmp/x.cfg"},
		{"net", "http", "web1", "ftp://x"},
		{"net", "http", "web1", "localhost:8080"},
		{"net", "http", "web1", "http://x", "--expect", "abc"},
		{"net", "http", "web1", "http://x", "--expect", "600"},
	} {
		wantCode(t, "USAGE", append([]string{"--dry-run"}, args...)...)
	}
	mustRun(t, "net", "http", "web1", "https://x/health", "--expect", "2XX", "--dry-run")
	if !statusMatches(204, "2XX") || statusMatches(301, "2xx") {
		t.Error("2XX must match like 2xx")
	}
	defer func(d time.Duration) { g.timeout = d }(g.timeout)
	g.timeout = 0
	if curlSeconds() != 15 {
		t.Error("curl's default limit is 15s")
	}
	g.timeout = 5 * time.Second
	if curlSeconds() != 4 {
		t.Errorf("--timeout 5s: curl -m %d", curlSeconds())
	}
}

func TestUserLockGuardsTheLogin(t *testing.T) {
	devopsHome(t)
	for want, args := range map[string][]string{
		"komando out of web1: it is the user komando logs in as": {"user", "lock", "web1", "deploy"},
		"root on web1: root is the account":                      {"user", "lock", "web1", "root"},
		"komando out of web2: it is the user":                    {"user", "lock", "web1,web2", "ops"},
		"deleting deploy locks komando out of web1":              {"user", "rm", "web1", "deploy"},
	} {
		d := mustRun(t, append(args, "--dry-run")...)
		if b := blockedBy(d); !strings.Contains(b, want) {
			t.Errorf("%v: want %q, got %s", args, want, b)
		}
	}
	for _, sh := range []string{"/usr/sbin/nologin", "/bin/false"} {
		for _, u := range []string{"deploy", "root"} {
			if b := blockedBy(mustRun(t, "user", "add", "web1", u, "--shell", sh, "--dry-run")); b == "" {
				t.Errorf("user add %s --shell %s is not blocked", u, sh)
			}
		}
	}
	if b := blockedBy(mustRun(t, "user", "add", "web1", "deploy", "--shell", "/bin/zsh", "--dry-run")); b != "" {
		t.Errorf("a login shell is fine: %s", b)
	}
	if b := blockedBy(mustRun(t, "user", "add", "web1", "alice", "--shell", "/usr/sbin/nologin", "--dry-run")); b != "" {
		t.Errorf("nologin for another user is fine: %s", b)
	}
	if b := blockedBy(mustRun(t, "user", "lock", "web1", "alice", "--dry-run")); b != "" {
		t.Errorf("another user is fine: %s", b)
	}
	wantCode(t, "POLICY_BLOCKED", "user", "lock", "web1", "deploy")
	if _, e := userResult("x", "locked", &sshx.RunResult{Stdout: "#komando:no-usermod\n", ExitCode: 127}); e == nil || e.Code != "TOOL_MISSING" {
		t.Errorf("busybox without usermod: %v", e)
	}
}

// user add and rm read the same markers through runFleet's exitMap.
func TestShadowMissing(t *testing.T) {
	for _, tool := range []string{"useradd", "userdel", "usermod"} {
		e := shadowMissing(&sshx.RunResult{Stdout: "#komando:no-" + tool + "\n", Stderr: tool + " is missing on this server", ExitCode: 127})
		if e == nil || e.Code != "TOOL_MISSING" || e.Exit != out.ExitNotFound || !strings.Contains(e.Message, tool) || !strings.Contains(e.Hint, "pkg install TARGET shadow") {
			t.Errorf("%s: %+v", tool, e)
		}
	}
	for _, rr := range []*sshx.RunResult{nil, {ExitCode: 1, Stderr: "useradd: user 'x' already exists"}, {Stdout: "#komando:no-user\n"}} {
		if e := shadowMissing(rr); e != nil {
			t.Errorf("%+v: unexpected %+v", rr, e)
		}
	}
}

func TestUserAddKeyAndPubkey(t *testing.T) {
	devopsHome(t)
	pub := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqT3xpp0F3DOT3pR0ZJ0sJ1ttRKtz2E0yHkGQ5w5GKJl ci@example.com"
	wantCode(t, "USAGE", "user", "add", "web1", "ci", "--key", "k1", "--pubkey", pub, "--dry-run")
}

func TestPkgUpdateTakesNoPackages(t *testing.T) {
	devopsHome(t)
	e := wantCode(t, "USAGE", "pkg", "update", "web1", "nginx", "--dry-run")
	if !strings.Contains(e.Hint, "pkg upgrade web1 nginx") {
		t.Errorf("hint %q", e.Hint)
	}
	mustRun(t, "pkg", "update", "web1", "--dry-run")
}

func TestWaitTakesDurations(t *testing.T) {
	devopsHome(t)
	mustRun(t, "svc", "restart", "web1", "nginx", "--wait", "10s", "--dry-run")
	if _, e := invRun(t, "svc", "restart", "web1", "nginx", "--wait", "10", "--dry-run"); e == nil || !strings.Contains(e.Message, "10s") {
		t.Errorf("--wait 10 names the units: %v", e)
	}
	if _, e := invRun(t, "svc", "restart", "web1", "nginx", "--wait", "soon", "--dry-run"); e == nil || !strings.Contains(e.Message, "--wait") {
		t.Errorf("--wait soon: %v", e)
	}
	mustRun(t, "reboot", "web1", "--wait", "600s", "--dry-run")
	for in, want := range map[string]time.Duration{"10s": 10 * time.Second, "2m": 2 * time.Minute, "1d": 24 * time.Hour} {
		var d time.Duration
		if err := (&durFlag{d: &d}).Set(in); err != nil || d != want {
			t.Errorf("%s: %v %v", in, d, err)
		}
	}
	for d, want := range map[time.Duration]string{0: "0", 10 * time.Minute: "10m", time.Hour: "1h", 90 * time.Second: "1m30s"} {
		if got := (&durFlag{d: &d}).String(); got != want {
			t.Errorf("%v shows as %s, want %s", d, got, want)
		}
	}
}

func TestSvcListFailedAndState(t *testing.T) {
	devopsHome(t)
	wantCode(t, "USAGE", "svc", "list", "web1", "--failed", "--state", "running", "--dry-run")
	mustRun(t, "svc", "list", "web1", "--failed", "--dry-run")
}

func TestContentListsTakeLs(t *testing.T) {
	devopsHome(t)
	for _, n := range []string{"svc", "cron", "user"} {
		mustRun(t, n, "ls", "web1", "--dry-run")
	}
}

func TestLogsFlagsChecked(t *testing.T) {
	devopsHome(t)
	for _, args := range [][]string{
		{"logs", "web1", "--unit", "nginx", "--timestamps"},
		{"logs", "web1", "--file", "rel/path"},
		{"logs", "web1", "--unit", "nginx", "--since", "bogus"},
		{"logs", "web1", "--container", "api", "--since", "2 hours ago"},
	} {
		wantCode(t, "USAGE", append(args, "--dry-run")...)
	}
	cases := []struct {
		o    logOpts
		want string
	}{
		{logOpts{unit: "nginx", since: "2h"}, "--since '-2h'"},
		{logOpts{unit: "nginx", since: "-30min"}, "--since '-30min'"},
		{logOpts{since: "2026-01-02T10:00"}, "--since '2026-01-02 10:00'"},
		{logOpts{since: "2026-01-02T10:00:00Z"}, "--since '2026-01-02 10:00:00 UTC'"},
		{logOpts{since: "today", until: "1 hour ago"}, "--until '1 hour ago'"},
		{logOpts{container: "api", since: "-7d"}, "--since '168h'"},
		{logOpts{container: "api", since: "2026-01-02 10:00"}, "--since '2026-01-02T10:00'"},
	}
	for _, c := range cases {
		if err := c.o.check(); err != nil {
			t.Errorf("%+v: %v", c.o, err)
			continue
		}
		if got := c.o.source(); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %s lacks %s", c.o, got, c.want)
		}
	}
}

func TestCertFlagsAndScheme(t *testing.T) {
	devopsHome(t)
	e := wantCode(t, "USAGE", "cert", "check", "http://example.com")
	if !strings.Contains(e.Message, "no certificate") || !strings.Contains(e.Hint, "https://example.com") {
		t.Errorf("http: %+v", e)
	}
	wantCode(t, "USAGE", "cert", "check", "example.com:443", "--path", "/etc/x", "--dry-run")
	wantCode(t, "USAGE", "cert", "check", "web1", "--via", "web2", "--dry-run")
	if e := wantCode(t, "USAGE", "cert", "check", "web1", "--warn", "soon"); !strings.Contains(e.Hint, "--warn") {
		t.Errorf("--warn hint %q", e.Hint)
	}
	if c := certTLSConfig("x"); !slices.Equal(c.CurvePreferences, []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}) {
		t.Errorf("curves %v", c.CurvePreferences)
	}
}

// A container's --since takes every journal-style time back from now and
// gets it as a Go duration, which docker reads.
func TestLogTimeForContainers(t *testing.T) {
	for in, want := range map[string]string{"30m": "30m", "2h": "2h", "7d": "168h", "1w": "168h", "90min": "90m", "1d2h": "26h", "-10m": "10m", "45secs": "45s"} {
		if got, err := logTime("--since", in, true); err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	if got, _ := logTime("--since", "1w", false); got != "-1w" {
		t.Errorf("journal: got %q", got)
	}
	// today, yesterday and now are the server's own midnight or time
	for _, v := range []string{"today", "yesterday", "now"} {
		if got, err := logTime("--since", v, true); err != nil || got != v {
			t.Errorf("%s for a container: %q %v", v, got, err)
		}
	}
	src := (&logOpts{container: "api", lines: 50, since: "yesterday", until: "today"}).source()
	for _, want := range []string{`--since "$(y=$(( $(date +%s) - 86400 ))`, `--until "$(date +%Y-%m-%dT00:00:00)"`} {
		if !strings.Contains(src, want) {
			t.Errorf("docker logs line lacks %q:\n%s", want, src)
		}
	}
	if _, err := logTime("--since", "2 hours ago", true); err == nil {
		t.Error("an \"ago\" time is the journal's only")
	}
}
