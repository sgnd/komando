package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// asAgent runs the rest of a test as Claude Code, with a person who answers
// the approval window with allow (or deny, or no window at all when shown
// is false). It returns how many windows were opened.
func asAgent(t *testing.T, allow, shown bool) *int {
	t.Helper()
	t.Setenv("CLAUDECODE", "1")
	n := new(int)
	saved := askOnScreen
	askOnScreen = func(text string) (bool, bool) {
		*n++
		if !strings.Contains(text, "Claude Code wants komando to run") {
			t.Errorf("window text: %q", text)
		}
		return allow && shown, shown
	}
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	resetApproval()
	return n
}

func TestWhoIsAsking(t *testing.T) {
	if isAgent() {
		t.Fatal("tests run as a script")
	}
	t.Setenv("GEMINI_CLI", "1")
	if agentName() != "Gemini CLI" {
		t.Errorf("agentName = %q", agentName())
	}
	t.Setenv("GEMINI_CLI", "0")
	if isAgent() {
		t.Error("GEMINI_CLI=0 is not an agent")
	}
}

func TestScriptFlagsWorkAsBefore(t *testing.T) {
	resetApproval()
	g.yes, g.allowDangerous = true, true
	defer func() { g.yes, g.allowDangerous = false, false }()
	if !yesOK() || !dangerOK() { // askOnScreen panics if it is called
		t.Fatal("a script's flags count")
	}
}

func TestAgentFlagsNeedAPerson(t *testing.T) {
	defer func() { g.yes, g.allowDangerous = false, false }()

	n := asAgent(t, true, true)
	g.yes, g.allowDangerous = true, true
	if !yesOK() || !dangerOK() {
		t.Fatal("the person allowed it")
	}
	if *n != 1 {
		t.Errorf("one command asks once, asked %d times", *n)
	}

	asAgent(t, false, true)
	if yesOK() {
		t.Fatal("the person denied it")
	}
	e := &out.Error{Code: "PROTECTED_HOST", Exit: out.ExitPolicy}
	approvalHint(e)
	if !strings.Contains(e.Hint, "Deny") {
		t.Errorf("hint after deny: %q", e.Hint)
	}

	asAgent(t, false, false)
	if dangerOK() {
		t.Fatal("no window, no yes")
	}
	e = &out.Error{Code: "POLICY_BLOCKED", Exit: out.ExitPolicy}
	approvalHint(e)
	if !strings.Contains(e.Hint, "own terminal") {
		t.Errorf("hint without a screen: %q", e.Hint)
	}

	n = asAgent(t, true, true)
	g.yes, g.allowDangerous = false, false
	if yesOK() || *n != 0 {
		t.Error("no flag, no window")
	}
}

func TestAgentSafetySettingThroughCommand(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		root.SetOut(&strings.Builder{})
		saved := out.P.W
		out.P.W = &strings.Builder{}
		defer func() { out.P.W = saved }()
		return root.Execute()
	}
	if err := run("policy", "deny", "kubectl apply"); err != nil {
		t.Fatal(err)
	}
	asAgent(t, false, true)
	err := run("policy", "allow", "kubectl apply", "--yes")
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "SAFETY_SETTING" {
		t.Fatalf("denied in the window: %v", err)
	}
	n := asAgent(t, true, true)
	if err := run("policy", "allow", "kubectl apply", "--yes"); err != nil || *n != 1 {
		t.Fatalf("allowed in the window: %v (windows %d)", err, *n)
	}
}

func TestAgentOutputIsMasked(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		saved := out.P.W
		out.P.W = &strings.Builder{}
		defer func() { out.P.W = saved }()
		return root.Execute()
	}
	if err := run("secret", "list"); err != nil || out.P.Mask {
		t.Fatalf("a script sees what the server sent (err %v)", err)
	}
	n := asAgent(t, false, true)
	if err := run("secret", "list"); err != nil || !out.P.Mask || *n != 0 {
		t.Fatalf("an agent sees [hidden] (err %v, windows %d)", err, *n)
	}
	n = asAgent(t, true, true)
	if err := run("secret", "list", "--reveal"); err != nil || out.P.Mask || *n != 1 {
		t.Fatalf("--reveal, allowed by the person (err %v, windows %d)", err, *n)
	}
	// secret get --reveal stays for a person at a terminal: no window
	n = asAgent(t, true, true)
	err := run("secret", "get", "nope", "--reveal")
	if *n != 0 || !out.P.Mask {
		t.Fatalf("secret get --reveal opened a window (err %v)", err)
	}
	out.P.Mask = false
}

func TestSensitiveName(t *testing.T) {
	for p, want := range map[string]bool{
		"/srv/app/.env": true, ".env.production": true, "prod.env": true, "/root/.ssh/id_ed25519": true,
		"/etc/ssl/private/site.key": true, "/etc/shadow": true, "config/master.key": true, "~/.aws/credentials": true,
		".env.example": false, "/srv/app/.env.sample": false, "/etc/nginx/nginx.conf": false, "id_ed25519.pub": false,
		"/var/log/syslog": false, "environment.ts": false,
	} {
		if sensitiveName(p) != want {
			t.Errorf("sensitiveName(%q) = %v", p, !want)
		}
	}
}

func TestHiddenPatternMatchesMaskedLine(t *testing.T) {
	src := "DB_HOST=db1\nDB_PASSWORD=s3cr;et\nAPI_TOKEN=abc123\n"
	masked := out.MaskSecrets(src)
	if strings.Contains(masked, "abc123") {
		t.Fatalf("not masked: %q", masked)
	}
	line := "API_TOKEN=" + out.Hidden
	re := regexp.MustCompile(hiddenPattern(line))
	if got := re.FindAllString(src, -1); len(got) != 1 || got[0] != "API_TOKEN=abc123" {
		t.Errorf("match: %q", got)
	}
	if err := hiddenValueErr(); !out.HasHidden(masked) || err == nil {
		t.Error("masked text must be refused for writing")
	}
}

func TestGuard(t *testing.T) {
	home := "/Users/me"
	t.Setenv("KOMANDO_HOME", "")
	cases := []struct {
		tool  string
		in    map[string]any
		block bool
	}{
		{"Read", map[string]any{"file_path": "/Users/me/.komando/vault.key"}, true},
		{"Read", map[string]any{"file_path": "/Users/me/.ssh/id_ed25519"}, true},
		{"Read", map[string]any{"file_path": "/Users/me/.ssh/id_ed25519.pub"}, false},
		{"Read", map[string]any{"file_path": "/Users/me/.ssh/config"}, false},
		{"Read", map[string]any{"file_path": "/Users/me/code/app/.env"}, true},
		{"Read", map[string]any{"file_path": "/Users/me/code/app/.env.example"}, false},
		{"Read", map[string]any{"file_path": "/Users/me/code/app/main.go"}, false},
		{"Edit", map[string]any{"file_path": "/Users/me/.aws/credentials"}, true},
		{"Read", map[string]any{"file_path": "/Users/me/.kube/config"}, true},
		{"Grep", map[string]any{"path": "/Users/me/.komando"}, true},
		{"Grep", map[string]any{"path": "/Users/me/code", "glob": "*.env"}, true},
		{"Glob", map[string]any{"path": "/Users/me/code"}, false},
		{"Bash", map[string]any{"command": "cat ~/.komando/vault.json"}, true},
		{"Bash", map[string]any{"command": "ls -la && cat $HOME/.ssh/id_rsa | base64"}, true},
		{"Bash", map[string]any{"command": "grep -r DB_ .env"}, true},
		{"Bash", map[string]any{"command": "source .env.production && npm start"}, true},
		{"Bash", map[string]any{"command": "echo $KOMANDO_VAULT_PASS"}, true},
		{"Bash", map[string]any{"command": "env"}, true},
		{"Bash", map[string]any{"command": "printenv | sort"}, true},
		{"Bash", map[string]any{"command": "ssh web1 uptime"}, true},
		{"Bash", map[string]any{"command": "sudo -E scp a web1:/tmp/"}, true},
		{"Bash", map[string]any{"command": "rsync -a ./site deploy@web1:/var/www"}, true},
		{"Bash", map[string]any{"command": "security find-generic-password -s x -w"}, true},
		{"Bash", map[string]any{"command": "cat /proc/1/environ"}, true},
		// allowed: komando itself, ordinary work, names without reading
		{"Bash", map[string]any{"command": "komando fs cat web1 /srv/app/.env"}, false},
		{"Bash", map[string]any{"command": "komando exec web1 'cat /etc/shadow' --read-only"}, false},
		{"Bash", map[string]any{"command": "set -euo pipefail; go test ./..."}, false},
		{"Bash", map[string]any{"command": "echo .env >> .gitignore"}, false},
		{"Bash", map[string]any{"command": "git commit -m 'load .env on start'"}, false},
		{"Bash", map[string]any{"command": "printenv PATH"}, false},
		{"Bash", map[string]any{"command": "env GOOS=linux go build ./..."}, false},
		{"Bash", map[string]any{"command": "export FOO=1 && rsync -a ./a ./b"}, false},
		{"Bash", map[string]any{"command": "ssh-keygen -lf ~/.ssh/id_ed25519.pub"}, false},
		{"Bash", map[string]any{"command": "grep -rn password src/"}, false},
		{"Bash", map[string]any{"command": "cp .env.example .env.local.example"}, false},
		{"WebFetch", map[string]any{"url": "https://example.com/.env"}, false},
	}
	for _, c := range cases {
		d := checkTool(c.tool, c.in, home)
		if d.Deny != c.block {
			t.Errorf("%s %v: deny=%v (%s)", c.tool, c.in, d.Deny, d.Reason)
		}
	}
}

func TestInstallGuardHook(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	other := `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"my-check"}]}]}}`
	if err := os.WriteFile(p, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := installGuardHook(p, "/opt/homebrew/bin/komando", false)
	if err != nil || f.Action != "updated" || f.Backup == "" {
		t.Fatalf("first install: %+v %v", f, err)
	}
	f, err = installGuardHook(p, "/opt/homebrew/bin/komando", false)
	if err != nil || f.Action != "unchanged" {
		t.Fatalf("second install: %+v %v", f, err)
	}
	var s struct {
		Model string `json:"model"`
		Hooks struct {
			Pre []struct {
				Matcher string                     `json:"matcher"`
				Hooks   []struct{ Command string } `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.Model != "opus" || len(s.Hooks.Pre) != 2 || s.Hooks.Pre[0].Hooks[0].Command != "my-check" ||
		s.Hooks.Pre[1].Hooks[0].Command != "/opt/homebrew/bin/komando guide guard" {
		t.Errorf("settings: %s", b)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installGuardHook(p, "komando", false); err == nil {
		t.Error("broken settings must be left alone")
	}
}
