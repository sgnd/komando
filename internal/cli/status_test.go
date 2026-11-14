package cli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

func TestRunningStatusEmpty(t *testing.T) {
	d := runningStatus(tcl, &store.State{Settings: store.DefaultSettings()})
	if d.Vpns == nil || d.AWSLogins == nil || d.Tunnels == nil || d.Jobs == nil {
		t.Errorf("empty lists must be [] in JSON, not null: %+v", d)
	}
	if got := d.Text(); got != "nothing running: no VPN sessions, server or AWS logins, tunnels or jobs\n" {
		t.Errorf("text: %q", got)
	}
}

func TestRunningStatus(t *testing.T) {
	saved := sessionAlive
	defer func() { sessionAlive = saved }()
	sessionAlive = func(s *store.VpnSession) bool { return s.PID == 100 }

	now := time.Now()
	st := &store.State{
		Settings: store.DefaultSettings(), // vpn_idle 30m
		Hosts:    map[string]*store.Host{"db1": {Name: "db1", Via: "office"}},
		Vpns: map[string]*store.Vpn{
			"office": {Name: "office", Kind: "openvpn"},
			"old":    {Name: "old", Kind: "openvpn"},
			"never":  {Name: "never", Kind: "wireguard"},
		},
		// office was used a second over 3m ago: the clock may not move
		// while the test runs (Windows), and 27m left reads as 27m
		Sessions: map[string]*store.VpnSession{
			"office": {Vpn: "office", PID: 100, StartedAt: now.Add(-42 * time.Minute), LastUsed: now.Add(-3*time.Minute - time.Second)},
			"old":    {Vpn: "old", PID: 200, StartedAt: now.Add(-time.Hour), LastUsed: now.Add(-time.Hour)}, // died
		},
		Tunnels: map[string]*store.Tunnel{
			"t-up":   {ID: "t-up", Host: "bastion", Kind: "local", Spec: "5433:10.0.0.9:5432", Conn: "app-db", PID: os.Getpid(), StartedAt: now.Add(-2 * time.Hour)},
			"t-dead": {ID: "t-dead", Host: "bastion", Kind: "local", Spec: "1:2:3", PID: 1 << 30, StartedAt: now},
		},
		Jobs: map[string]*store.Job{
			"j-1": {ID: "j-1", Host: "web1", Command: "pg_dump app | gzip > /backup/app.sql.gz && echo done && echo \x1b[2J" + strings.Repeat("x", 40), StartedAt: now.Add(-15 * time.Minute)},
		},
	}
	d := runningStatus(tcl, st)
	if len(d.Vpns) != 1 || d.Vpns[0].Name != "office" {
		t.Fatalf("only live sessions: %+v", d.Vpns)
	}
	if got := d.Vpns[0].ClosesAt; !got.Equal(st.Sessions["office"].LastUsed.Add(30 * time.Minute)) {
		t.Errorf("closes_at: %v", got)
	}
	if len(d.Vpns[0].UsedBy) != 1 || d.Vpns[0].UsedBy[0] != "db1" {
		t.Errorf("used_by: %v", d.Vpns[0].UsedBy)
	}
	if len(d.Tunnels) != 1 || d.Tunnels[0].ID != "t-up" {
		t.Errorf("only live tunnels: %+v", d.Tunnels)
	}
	if len(d.Jobs) != 1 {
		t.Errorf("jobs: %+v", d.Jobs)
	}

	text := d.Text()
	for _, want := range []string{
		"vpn", "office", "used 3m ago, closes in 26m if unused", "42m",
		"tunnel", "t-up", "→ app-db", "2h",
		"job", "j-1", "web1: pg_dump app", "…", "15m",
		"`komando job list --refresh`",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text misses %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "old") || strings.Contains(text, "t-dead") {
		t.Errorf("text shows escapes or things that are not running:\n%s", text)
	}

	// vpn_idle 0: a session never closes by itself
	st.Settings.VpnIdle = "0"
	if d := runningStatus(tcl, st); !d.Vpns[0].ClosesAt.IsZero() {
		t.Errorf("no idle limit, no closes_at: %v", d.Vpns[0].ClosesAt)
	}
}

// TestStatusCommand runs `komando status` itself: it works on an empty
// home and changes nothing.
func TestStatusCommand(t *testing.T) {
	setHome(t, t.TempDir())
	if err := store.Update(store.Save, func(st *store.State) error {
		st.Jobs["j-1"] = &store.Job{ID: "j-1", Host: "nowhere", Command: "sleep 1"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(store.Path("state.json"))
	rtBefore, _ := os.ReadFile(store.Path("runtime.json"))
	root := newRoot(tcl)
	t.Cleanup(endCommand) // the next test starts with none of this command's flags
	root.SetArgs([]string{"-o", "json", "status"})
	if err := root.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	after, _ := os.ReadFile(store.Path("state.json"))
	if string(before) != string(after) {
		t.Error("status changed the state file")
	}
	if rtAfter, _ := os.ReadFile(store.Path("runtime.json")); string(rtBefore) != string(rtAfter) {
		t.Error("status changed the runtime file")
	}
}
