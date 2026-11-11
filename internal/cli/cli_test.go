package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func TestMain(m *testing.M) {
	// never wait for a confirmation prompt, even when run from a terminal
	interactive = func() bool { return false }
	// tests run as a script, even inside an AI agent's shell; the ones about
	// agents set the variables themselves
	for _, a := range agentVars {
		os.Unsetenv(a.env)
		resetApproval()
	}
	askOnScreen = func(string) (bool, bool) { panic("a test opened an approval window") }
	// a new vault never puts its key in the login keychain of whoever runs
	// the tests (secret_keychain_test.go uses stand-ins)
	os.Setenv("KOMANDO_KEYCHAIN", "off")
	// every command opens the sealed store with the passphrase: a cheap
	// scrypt keeps the PTY children (this binary again) fast under -race
	vault.PassphraseN = 1 << 10
	// each test keeps komando's data in its own KOMANDO_HOME, as the
	// person's usual folder; TestAgentOtherHome checks the real rule
	realHome := defaultHome
	defaultHome = func() string {
		if h := os.Getenv("KOMANDO_HOME"); h != "" {
			return h
		}
		return realHome()
	}
	os.Exit(m.Run())
}

func testState() *store.State {
	s := &store.State{Hosts: map[string]*store.Host{}}
	add := func(name string, groups, tags []string, labels map[string]string) {
		s.Hosts[name] = &store.Host{Name: name, Address: name + ".lan", Groups: groups, Tags: tags, Labels: labels}
	}
	add("web-1", []string{"web"}, []string{"prod"}, map[string]string{"dc": "jkt"})
	add("web-2", []string{"web"}, []string{"prod"}, map[string]string{"dc": "sgp"})
	add("db-1", []string{"db"}, []string{"prod"}, map[string]string{"dc": "jkt"})
	add("dev-1", nil, []string{"dev"}, nil)
	return s
}

func TestResolveTargets(t *testing.T) {
	st := testState()
	cases := map[string]string{
		"web-1":             "web-1",
		"@web":              "web-1,web-2",
		"tag:prod":          "db-1,web-1,web-2",
		"label:dc=jkt":      "db-1,web-1",
		"web-*":             "web-1,web-2",
		"all":               "db-1,dev-1,web-1,web-2",
		"all,!tag:prod":     "dev-1",
		"@web,db-1":         "db-1,web-1,web-2",
		"tag:prod,!web-2":   "db-1,web-1",
		"root@1.2.3.4:2222": "root@1.2.3.4:2222",
	}
	for expr, want := range cases {
		hs, err := resolveTargets(st, expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := strings.Join(hostNames(hs), ","); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
	if _, err := resolveTargets(st, "nope"); err == nil || toErr(err).Code != "HOST_NOT_FOUND" {
		t.Errorf("expected HOST_NOT_FOUND, got %v", err)
	}
	if _, err := resolveTargets(st, "@missing"); err == nil || toErr(err).Code != "TARGET_EMPTY" {
		t.Errorf("expected TARGET_EMPTY, got %v", err)
	}
}

func TestRender(t *testing.T) {
	got, err := render("echo {{who}} {{n=3}} {{path}}", map[string]string{"path": "/"}, map[string]string{"who": "it's"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `echo 'it'"'"'s' '3' '/'`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if _, err := render("x {{need}}", nil, nil); err == nil {
		t.Error("expected missing parameter error")
	}
	// docker-style templates are left alone
	if got, _ := render("docker ps --format '{{.Names}}'", nil, nil); !strings.Contains(got, "{{.Names}}") {
		t.Errorf("docker template mangled: %s", got)
	}
}

func TestParseSSHConfig(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "extra.conf")
	os.WriteFile(inc, []byte("Host extra\n  HostName 9.9.9.9\n"), 0o600)
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte(`Include extra.conf
Host web
  HostName 10.0.0.1
  Port 2200
  User deploy
  ProxyJump bastion
Host bastion
  HostName bastion.example.com
  ServerAliveInterval 30
Host ec2
  HostName i-0abc
  ProxyCommand aws ssm start-session --target %h
Match host *.internal
  User ops
Host *
  User fallback
`), 0o600)
	hosts, notes, err := parseSSHConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*store.Host{}
	for _, h := range hosts {
		by[h.Name] = h
	}
	if w := by["web"]; w == nil || w.Address != "10.0.0.1" || w.Port != 2200 || w.User != "deploy" || w.Via != "bastion" {
		t.Errorf("web parsed wrong: %+v", w)
	}
	if b := by["bastion"]; b == nil || b.User != "fallback" {
		t.Errorf("wildcard default not applied: %+v", b)
	}
	if by["extra"] == nil || by["extra"].Address != "9.9.9.9" {
		t.Error("Include not followed")
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "Match block") || strings.Contains(joined, "proxycommand") {
		t.Errorf("notes must report Match, and ProxyCommand is carried over now: %q", notes)
	}
	if e := by["ec2"]; e == nil || e.ProxyCommand != "aws ssm start-session --target %h" {
		t.Errorf("ProxyCommand not carried over: %+v", e)
	}
	if strings.Contains(joined, "serveraliveinterval") || strings.Contains(joined, "bastion:") {
		t.Errorf("harmless directives must not be reported: %q", notes)
	}
}

func TestSplitRemote(t *testing.T) {
	cases := []struct {
		in, target, path string
		remote           bool
	}{
		{"web1:/tmp/x", "web1", "/tmp/x", true},
		{"@web:/etc/hosts", "@web", "/etc/hosts", true},
		{"./local:file", "", "./local:file", false},
		{"/abs/path", "", "/abs/path", false},
		{"file.txt", "", "file.txt", false},
	}
	for _, c := range cases {
		tg, p, ok := splitRemote(c.in)
		if tg != c.target || p != c.path || ok != c.remote {
			t.Errorf("%s: got (%s,%s,%v)", c.in, tg, p, ok)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	d := unifiedDiff("a\nb\nc\n", "a\nB\nc\n", 1)
	if !strings.Contains(d, "-b\n") || !strings.Contains(d, "+B\n") {
		t.Errorf("bad diff:\n%s", d)
	}
}

// auditText is every audit record, one per line, from the file or the
// sealed store.
func auditText(t *testing.T) string {
	t.Helper()
	var lines []string
	if err := eachAudit(func(_ int, b []byte) error { lines = append(lines, string(b)); return nil }); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}
