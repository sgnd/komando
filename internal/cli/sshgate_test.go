package cli

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

func TestGateWords(t *testing.T) {
	ok := map[string][]string{
		"komando list":      {"komando", "list"},
		"  komando\tlist  ": {"komando", "list"},
		"komando exec web --read-only -- 'echo a; echo b'": {"komando", "exec", "web", "--read-only", "--", "echo a; echo b"},
		`komando exec web -- "a b" c`:                      {"komando", "exec", "web", "--", "a b", "c"},
		`komando list web-* ~ db-?`:                        {"komando", "list", "web-*", "~", "db-?"}, // nothing is expanded
		`komando x "a\"b\\c\$d" 'e\f'`:                     {"komando", "x", `a"b\c$d`, `e\f`},
		`komando a\ b \;`:                                  {"komando", "a b", ";"},
		`komando '' "" x`:                                  {"komando", "", "", "x"},
		"komando 'line one\nline two'":                     {"komando", "line one\nline two"},
		"komando list\\\n web":                             {"komando", "list", "web"},
		`komando a'b'"c"d`:                                 {"komando", "abcd"},
		`komando x#y`:                                      {"komando", "x#y"},
	}
	for in, want := range ok {
		got, err := gateWords(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"komando list; id", "komando list | sh", "komando list && id", "komando list || id", "komando list &",
		"komando $(id)", "komando `id`", `komando "$HOME"`, "komando \"`id`\"", "komando $HOME",
		"komando list > /tmp/x", "komando list < /etc/passwd", "komando (list)",
		"komando list\nid", "komando list\rid", "komando list #comment",
		"komando 'open", `komando "open`, `komando list \`,
	} {
		if got, err := gateWords(in); err == nil {
			t.Errorf("%q: accepted as %q", in, got)
		}
	}
}

func TestParseGate(t *testing.T) {
	req, e := parseGate("KOMANDO_AGENT='Komando iPhone' komando list -o json")
	if e != nil || req.agent != "Komando iPhone" || !slices.Equal(req.args, []string{"list", "-o", "json"}) {
		t.Errorf("%+v %v", req, e)
	}
	for in, code := range map[string]string{
		"":                               "SSH_GATE_REFUSED",
		"   ":                            "SSH_GATE_REFUSED",
		"ls -la":                         "SSH_GATE_REFUSED",
		"bash -c 'komando list'":         "SSH_GATE_REFUSED",
		"/usr/local/bin/komando list":    "SSH_GATE_REFUSED",
		"scp -t /tmp":                    "SSH_GATE_REFUSED",
		"/usr/lib/openssh/sftp-server":   "SSH_GATE_REFUSED",
		"PATH=/tmp komando list":         "SSH_GATE_REFUSED",
		"KOMANDO_HOME=/tmp komando list": "SSH_GATE_REFUSED",
		"KOMANDO_AGENT=x KOMANDO_AGENT=y komando list": "SSH_GATE_REFUSED",
		"KOMANDO_AGENT=x":         "SSH_GATE_REFUSED",
		"komando list; sh":        "SSH_GATE_SYNTAX",
		"export PATH=x; komando ": "SSH_GATE_SYNTAX",
	} {
		if _, e := parseGate(in); e == nil || e.Code != code {
			t.Errorf("%q: %+v, want %s", in, e, code)
		} else if want := map[string]int{"SSH_GATE_REFUSED": out.ExitPolicy, "SSH_GATE_SYNTAX": out.ExitUsage}[code]; e.Exit != want {
			t.Errorf("%q: exit %d, want %d", in, e.Exit, want)
		}
	}
}

// gateAnswer runs gateCheck on a command line ("" = allowed).
func gateAnswer(t *testing.T, line string, readOnly bool) string {
	t.Helper()
	words, err := gateWords(line)
	if err != nil {
		t.Fatal(err)
	}
	_, _, e := gateCheck(words, readOnly)
	if e == nil {
		return ""
	}
	if e.Exit != out.ExitPolicy || e.Hint == "" {
		t.Errorf("%q: %+v", line, e)
	}
	return e.Code
}

func TestGateCheck(t *testing.T) {
	invHome(t)
	mustRun(t, "recipe", "add", "my-df", "df -h", "--read-only")
	mustRun(t, "recipe", "add", "my-clean", "rm -rf /tmp/cache")
	g.yes = true // the gate's own flags come back after it read the key's
	defer func() { g.yes = false }()
	cases := []struct {
		line           string
		full, readOnly string
	}{
		{"list", "", ""},
		{"", "", ""}, // `komando` alone: first steps
		{"host list -o json", "", ""},
		{"secret get db --reveal", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"secret get db --reveal=true", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"secret get db --reveal=false", "", ""},
		{"--reveal secret get db", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"}, // a global flag before the command
		{"-o json --allow-dangerous fs rm web /tmp/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"exec web --allow-dangerous -- rm -rf /tmp/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"exec web --read-only -- echo --reveal --allow-dangerous", "", ""}, // words for the server
		{"shell web", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"db shell pg", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"cluster shell k8s pod/x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"secret passphrase", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"secret check db", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"login aws", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"config approval-code", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"ssh-gate --name x", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"ssh-gate line --name x key", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"guide guard", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"__complete exec ''", "SSH_GATE_REFUSED", "SSH_GATE_REFUSED"},
		{"host add x u@10.0.0.9", "", "SSH_GATE_READ_ONLY"},
		{"secret set db", "", "SSH_GATE_READ_ONLY"},
		{"svc restart web nginx", "", "SSH_GATE_READ_ONLY"},
		{"exec web -- uptime", "", "SSH_GATE_READ_ONLY"},
		{"exec web --read-only -- uptime", "", ""},
		{"docker exec web app ls", "", "SSH_GATE_READ_ONLY"},
		{"docker exec web app --read-only ls", "", ""},
		{"db query pg 'select 1'", "", ""},
		{"db query pg --write 'delete from t'", "", "SSH_GATE_READ_ONLY"},
		{"db explain pg --analyze 'delete from t'", "", "SSH_GATE_READ_ONLY"},
		{"cache run c --write SET a b", "", "SSH_GATE_READ_ONLY"},
		{"cluster run k8s --write delete pod x", "", "SSH_GATE_READ_ONLY"},
		{"pkg upgradable web --refresh", "", "SSH_GATE_READ_ONLY"},
		{"pkg security web --apply", "", "SSH_GATE_READ_ONLY"},
		{"pkg security web", "", ""},
		{"recipe run my-df web", "", ""},
		{"recipe run my-clean web", "", "SSH_GATE_READ_ONLY"},
		{"recipe run drop-caches web", "", "SSH_GATE_READ_ONLY"},
		{"recipe run dns web", "", ""},
		{"secret rm db --help", "", ""}, // help only
		{"db", "", ""},                  // a group: prints its help
		{"no-such-command", "", ""},     // komando says so, and runs nothing
		{"completion bash", "", ""},
		{"exec web --read-only --dry-run -- uptime", "", ""},
		{"host rm x --dry-run", "", "SSH_GATE_READ_ONLY"}, // a read-only key does not preview changes
		{"script web ./check.sh", "", "SSH_GATE_READ_ONLY"},
		{"script web ./check.sh --read-only", "", ""},
		{"job start web --read-only -- du -sh /var", "", ""},
		{"job start web -- make backup", "", "SSH_GATE_READ_ONLY"},
		{"cluster exec k8s pod/x -- ls", "", "SSH_GATE_READ_ONLY"},
		{"cluster exec k8s pod/x --read-only -- ls", "", ""},
		{"docker compose web ps", "", "SSH_GATE_READ_ONLY"}, // decided by the subcommand: not for a read key
		{"cp web:/etc/hosts /tmp/hosts", "", "SSH_GATE_READ_ONLY"},
		{"download web /etc/hosts", "", "SSH_GATE_READ_ONLY"},
		{"db dump pg --to /tmp/x.sql", "", "SSH_GATE_READ_ONLY"},
		{"storage link s3 report.pdf", "", "SSH_GATE_READ_ONLY"},
		{"cluster forward k8s svc/web 8080", "", "SSH_GATE_READ_ONLY"},
		{"host export", "", ""},
		{"facts web", "", ""},
		{"update", "", "SSH_GATE_READ_ONLY"},
	}
	for _, c := range cases {
		if got := gateAnswer(t, c.line, false); got != c.full {
			t.Errorf("%q: %q, want %q", c.line, got, c.full)
		}
		if got := gateAnswer(t, c.line, true); got != c.readOnly {
			t.Errorf("%q --read-only: %q, want %q", c.line, got, c.readOnly)
		}
	}
	if !g.yes || g.reveal {
		t.Errorf("the gate's own flags changed: %+v", g)
	}
}

// Every command a read-only key runs exists: a renamed one would silently
// leave the list.
func TestGateReadsExist(t *testing.T) {
	names := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		names[commandName(c)] = true
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRoot())
	for n := range gateReadForm {
		if !names[n] {
			t.Errorf("gateReadForm names %q, which is no command", n)
		}
	}
	for n := range gateNotForReadKey {
		if !names[n] {
			t.Errorf("gateNotForReadKey names %q, which is no command", n)
		}
	}
	for n := range gateNeedsPerson {
		if !names[n] {
			t.Errorf("gateNeedsPerson names %q, which is no command", n)
		}
	}
}

// gateRun runs `komando ssh-gate` as sshd would, for SSH_ORIGINAL_COMMAND
// line, and returns what it ran (nil when it ran nothing).
func gateRun(t *testing.T, line string, gateArgs ...string) (ran []string, env []string, e *out.Error) {
	t.Helper()
	t.Setenv("SSH_ORIGINAL_COMMAND", line)
	t.Setenv("SSH_CONNECTION", "203.0.113.7 51000 10.0.0.2 22")
	saved := gateExec
	defer func() { gateExec = saved }()
	gateExec = func(path string, argv, envv []string) error {
		ran, env = argv, envv
		return errors.New("stand-in for exec")
	}
	_, e = invRun(t, append([]string{"ssh-gate"}, gateArgs...)...)
	return ran, env, e
}

// lastAudit is the newest record in the audit log.
func lastAudit(t *testing.T) map[string]any {
	t.Helper()
	f, err := os.Open(store.Path("audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		last = nil
		_ = json.Unmarshal(sc.Bytes(), &last)
	}
	return last
}

func TestSSHGateRuns(t *testing.T) {
	invHome(t)
	ran, env, e := gateRun(t, "KOMANDO_AGENT=Komando komando list -o json", "--name", "phone")
	if !slices.Equal(ran, []string{"komando", "list", "-o", "json"}) {
		t.Fatalf("ran %q (%+v)", ran, e)
	}
	has := func(kv string) bool { return slices.Contains(env, kv) }
	if !has("KOMANDO_SSH_GATE=phone") || !has("KOMANDO_NO_DIALOG=1") || !has("KOMANDO_VAULT_PASS=test-passphrase-long-enough") {
		t.Errorf("env lacks the gate's variables or the vault passphrase")
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "SSH_ORIGINAL_COMMAND=") || strings.HasPrefix(kv, "KOMANDO_AGENT=") {
			t.Errorf("env passes %s on", kv)
		}
	}
	a := lastAudit(t)
	for k, want := range map[string]any{"command": "ssh-gate", "ok": true, "ssh_gate": "phone", "agent": "ssh-gate key phone",
		"runs": "list", "client": "203.0.113.7", "client_agent": "Komando", "read_only": false} {
		if a[k] != want {
			t.Errorf("audit %s = %v, want %v", k, a[k], want)
		}
	}
}

func TestSSHGateRefuses(t *testing.T) {
	invHome(t)
	for line, code := range map[string]string{
		"komando secret get db --reveal": "SSH_GATE_REFUSED",
		"sh -c id":                       "SSH_GATE_REFUSED",
		"":                               "SSH_GATE_REFUSED",
		"komando list; id":               "SSH_GATE_SYNTAX",
		"komando host add x u@10.0.0.9":  "SSH_GATE_READ_ONLY",
	} {
		ran, _, e := gateRun(t, line, "--name", "phone-read", "--read-only")
		if ran != nil || e == nil || e.Code != code {
			t.Errorf("%q: ran %q, error %+v, want %s", line, ran, e, code)
			continue
		}
		a := lastAudit(t)
		if a["ok"] != false || a["blocked"] != code || a["ssh_gate"] != "phone-read" || a["read_only"] != true || a["reason"] == "" {
			t.Errorf("%q: audit %v", line, a)
		}
	}
	if _, _, e := gateRun(t, "komando list", "--name", "bad name"); e == nil || e.Code != "USAGE" {
		t.Errorf("a bad --name: %+v", e)
	}
}

// What a key sent is kept in the audit log with secret-looking values
// hidden, as other records are.
func TestSSHGateAuditHidesSecrets(t *testing.T) {
	invHome(t)
	gateRun(t, "komando conn add pg postgres://app:S3cretPw@db.lan/shop", "--name", "phone")
	a := lastAudit(t)
	if s, _ := a["ssh_command"].(string); strings.Contains(s, "S3cretPw") || !strings.Contains(s, "conn add pg") {
		t.Errorf("ssh_command %q", s)
	}
}

// The komando a key runs is an agent named after the key; a name ssh-gate
// could not have set is not shown as it is.
func TestGateAgentName(t *testing.T) {
	t.Setenv(gateEnv, "phone")
	if got := agentName(); got != "ssh-gate key phone" {
		t.Errorf("agent %q", got)
	}
	t.Setenv("CLAUDECODE", "1") // set in the account's shell files, say
	if got := agentName(); got != "ssh-gate key phone" {
		t.Errorf("with CLAUDECODE too: agent %q", got)
	}
	os.Unsetenv("CLAUDECODE") // t.Setenv puts it back afterwards
	t.Setenv(gateEnv, "x\n\nkomando list wants")
	if got := agentName(); got != "An SSH key through ssh-gate" {
		t.Errorf("agent %q", got)
	}
}

func TestSSHGateLine(t *testing.T) {
	invHome(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	d := mustRun(t, "ssh-gate", "line", "--name", "phone", key+" my phone")
	line, _ := d["line"].(string)
	self := komandoPath()
	want := `restrict,command="` + gateShellQuote(self) + ` ssh-gate --name phone" ` + key + " my phone"
	if line != want || !filepath.IsAbs(self) {
		t.Errorf("line\n%s\nwant\n%s", line, want)
	}
	// the line is one sshd reads: restrict and the command, the same key
	got, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || !slices.Equal(opts, []string{"restrict", `command="` + gateShellQuote(self) + ` ssh-gate --name phone"`}) || string(got.Marshal()) != string(sp.Marshal()) {
		t.Errorf("sshd would read %v %v", opts, err)
	}

	pf := filepath.Join(t.TempDir(), "phone.pub")
	os.WriteFile(pf, []byte(key+" from a file\n"), 0o600)
	d = mustRun(t, "ssh-gate", "line", "--name", "phone-read", "--read-only", pf)
	if l, _ := d["line"].(string); !strings.Contains(l, ` ssh-gate --name phone-read --read-only" `+key+" from a file") {
		t.Errorf("from a file, read-only: %s", l)
	}

	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "phone", `restrict,command="sh" `+key)
	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "phone", "not a key")
	wantCode(t, "USAGE", "ssh-gate", "line", "--name", "a b", key)
	if _, e := invRun(t, "ssh-gate", "line", key); e == nil {
		t.Error("no --name: accepted")
	}
}

func TestGateShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/komando":       "/usr/local/bin/komando",
		"/Users/Jo Doe/go/bin/komando": "'/Users/Jo Doe/go/bin/komando'",
		"/opt/it's/komando":            `'/opt/it'\''s/komando'`,
	} {
		if got := gateShellQuote(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
