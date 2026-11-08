package cli

import (
	"fmt"
	"testing"
	"time"
)

func TestParseWhen(t *testing.T) {
	zone := time.FixedZone("T", 7*3600)
	now := time.Date(2026, 11, 8, 15, 4, 5, 0, zone)
	midnight := time.Date(2026, 11, 8, 0, 0, 0, 0, zone)
	for _, c := range []struct {
		in   string
		want time.Time
	}{
		{"30m", now.Add(-30 * time.Minute)},
		{"-2h", now.Add(-2 * time.Hour)},
		{"7d", now.Add(-7 * 24 * time.Hour)},
		{"-1d", now.Add(-24 * time.Hour)},
		{"today", midnight},
		{" Yesterday ", midnight.AddDate(0, 0, -1)},
		{"2026-11-07", time.Date(2026, 11, 7, 0, 0, 0, 0, zone)},
		{"2026-11-07 14:30", time.Date(2026, 11, 7, 14, 30, 0, 0, zone)},
		{"2026-11-07T14:30:15", time.Date(2026, 11, 7, 14, 30, 15, 0, zone)},
		{"2026-11-07T14:30:00Z", time.Date(2026, 11, 7, 14, 30, 0, 0, time.UTC)},
	} {
		got, err := parseWhen(c.in, "--since", now)
		if err != nil || !got.Equal(c.want) {
			t.Errorf("%q: got %v, %v; want %v", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "soon", "0d", "-0h", "1x", "2026-13-01", "11/07/2026"} {
		_, err := parseWhen(bad, "--until", now)
		if e := toErr(err); e == nil || e.Code != "USAGE" {
			t.Errorf("%q: want USAGE, got %v", bad, err)
		}
	}
}

func TestAuditFilterKeep(t *testing.T) {
	at := func(s string) map[string]any { return map[string]any{"ts": s, "command": "exec", "ok": true} }
	f := auditFilter{
		since: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC),
		until: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC),
	}
	for ts, want := range map[string]bool{
		"2026-11-06T23:59:59.999Z":       false,
		"2026-11-07T00:00:00Z":           true, // --since is inclusive
		"2026-11-07T12:00:00.123456789Z": true,
		"2026-11-08T06:59:59+07:00":      true,  // 23:59:59 UTC on the 7th
		"2026-11-08T00:00:00Z":           false, // --until is exclusive
		"not a time":                     false,
		"":                               false,
	} {
		if got := f.keep(at(ts)); got != want {
			t.Errorf("ts %q: keep %v, want %v", ts, got, want)
		}
	}
	if !(auditFilter{}).keep(map[string]any{"command": "exec"}) {
		t.Error("without a window, an entry without a time stays")
	}
	tgt := auditFilter{byTarget: true}
	if tgt.keep(map[string]any{"hosts": []any{"web1"}}) {
		t.Error("a --target that matches nothing keeps nothing")
	}
	tgt.names = map[string]bool{"db1": true}
	if !tgt.keep(map[string]any{"hosts": []any{"web1"}, "conns": []any{"db1"}}) {
		t.Error("a conn named by --target keeps the entry")
	}
	if (auditFilter{command: "host.", failed: true}).keep(map[string]any{"command": "host.add", "ok": true}) {
		t.Error("--failed drops a success")
	}
}

func TestInvAuditWindow(t *testing.T) {
	invHome(t)
	for i := range 52 {
		mustRun(t, "host", "add", fmt.Sprintf("w%d", i), fmt.Sprintf("u@10.0.1.%d", i+1))
	}
	if d := mustRun(t, "audit"); d["count"].(float64) != 50 {
		t.Errorf("default shows the newest 50, got %v", d["count"])
	}
	if d := mustRun(t, "audit", "--since", "1h"); d["count"].(float64) < 52 {
		t.Errorf("--since alone shows every match, got %v", d["count"])
	}
	if d := mustRun(t, "audit", "--since", "today", "-n", "5"); d["count"].(float64) != 5 {
		t.Errorf("-n still limits a window, got %v", d["count"])
	}
	if d := mustRun(t, "audit", "--until", "1h"); d["count"].(float64) != 0 {
		t.Errorf("nothing is older than an hour, got %v", d["count"])
	}
	if d := mustRun(t, "audit", "--since", "1h", "--target", "w3"); d["count"].(float64) != 1 {
		t.Errorf("--target with --since, got %v", d["count"])
	}
	wantCode(t, "USAGE", "audit", "--since", "soon")
	wantCode(t, "USAGE", "audit", "--since", "2026-11-08", "--until", "2026-11-07")
}
