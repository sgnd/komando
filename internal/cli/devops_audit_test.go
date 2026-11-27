package cli

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"

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
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["win1"] = &store.Host{Name: "win1", Address: "10.255.255.3", User: "Administrator", OS: store.OSWindows}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCertCheckRefusesWindows(t *testing.T) {
	devopsHome(t)
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

func TestPkgUpdateTakesNoPackages(t *testing.T) {
	devopsHome(t)
	e := wantCode(t, "USAGE", "pkg", "update", "web1", "nginx", "--dry-run")
	if !strings.Contains(e.Hint, "pkg upgrade web1 nginx") {
		t.Errorf("hint %q", e.Hint)
	}
	mustRun(t, "pkg", "update", "web1", "--dry-run")
}

func TestWaitTakesDurations(t *testing.T) {
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
