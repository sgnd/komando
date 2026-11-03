package cli

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/sgnd/komando/internal/store"
)

func TestStatusLineFormat(t *testing.T) {
	for _, c := range []struct {
		s     statusLine
		color bool
		want  string
	}{
		{statusLine{What: "shell", Target: "web1"}, false, "komando: shell on web1"},
		{statusLine{What: "shell", Target: "web1", Detail: "deploy@10.0.1.5", Route: []string{"vpn telkomsel", "bastion1"}}, false,
			"komando: shell on web1 (deploy@10.0.1.5) via vpn telkomsel → bastion1"},
		{statusLine{What: "shell", Target: "prod", Protected: true}, false, "komando: shell on prod · PROTECTED"},
		{statusLine{What: "shell", Target: "prod", Protected: true}, true, "komando: shell on prod · \x1b[1;31mPROTECTED\x1b[0m"},
		{statusLine{What: "psql", Target: "app-db", Detail: "read-only", Route: []string{"bastion1"}}, false,
			"komando: psql on app-db (read-only) via bastion1"},
		{statusLine{What: "following logs", Target: "web1, web2", Tail: "Ctrl-C stops"}, false,
			"komando: following logs on web1, web2 (Ctrl-C stops)"},
		// a name cannot smuggle escape sequences in
		{statusLine{What: "shell", Target: "evil\x1b]0;pwned\x07\r\n", Detail: "a\u202eb"}, false, "komando: shell on evil]0;pwned (ab)"},
	} {
		if got := c.s.format(c.color); got != c.want {
			t.Errorf("format(%+v, %v)\n got %q\nwant %q", c.s, c.color, got, c.want)
		}
	}
}

func TestExitLine(t *testing.T) {
	if got := exitLine("web1", 0, false, 12*time.Minute+4*time.Second); got != "komando: left web1 (exit 0, 12m)" {
		t.Errorf("exit: %q", got)
	}
	if got := exitLine("web1", 3, false, 5*time.Second); got != "komando: left web1 (exit 3, 5s)" {
		t.Errorf("exit 3: %q", got)
	}
	if got := exitLine("web1", 0, true, 3*time.Minute); got != "komando: connection to web1 lost after 3m" {
		t.Errorf("lost: %q", got)
	}
}

func TestStatusRoutes(t *testing.T) {
	st := &store.State{
		Hosts: map[string]*store.Host{
			"bastion": {Name: "bastion", Address: "10.0.0.1", Via: "office"},
			"web1":    {Name: "web1", Address: "10.0.1.5", Via: "bastion"},
			"direct":  {Name: "direct", Address: "10.0.1.6"},
			"broken":  {Name: "broken", Address: "10.0.1.7", Via: "a,b"},
		},
		Vpns: map[string]*store.Vpn{"office": {Name: "office", Kind: "wireguard"}},
	}
	check := func(name string, got []string, want string) {
		t.Helper()
		if strings.Join(got, " → ") != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
	check("host through vpn and bastion", hostRoute(st, st.Hosts["web1"]), "vpn office → bastion")
	check("direct host", hostRoute(st, st.Hosts["direct"]), "")
	check("broken path shows as written", hostRoute(st, st.Hosts["broken"]), "a → b")
	check("conn via host", connRoute(st, &store.Conn{Name: "db", Via: "web1"}), "vpn office → bastion → web1")
	check("conn via vpn", connRoute(st, &store.Conn{Name: "db", Via: "office"}), "vpn office")
	check("direct conn", connRoute(st, &store.Conn{Name: "db"}), "")
}

// TestStatusOnlyForPeople: agents and scripts never see a status line.
func TestStatusOnlyForPeople(t *testing.T) {
	saved := interactive
	defer func() { interactive = saved }()
	for _, person := range []bool{false, true} {
		interactive = func() bool { return person }
		got := captureStderr(t, func() {
			showStatus(statusLine{What: "shell", Target: "web1"})
			showExit("web1", 0, false, time.Second)
			noticef("vpn %s connected", "office")
		})
		if person != (got != "") {
			t.Errorf("person=%v: stderr %q", person, got)
		}
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = saved
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func FuzzCleanText(f *testing.F) {
	for _, s := range []string{"web1", "a\x1b[2Jb", "\u202ex", "日本 → 🚀", "\x9b31m"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range cleanText(s) {
			if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
				t.Fatalf("cleanText(%q) kept %U", s, r)
			}
		}
	})
}
