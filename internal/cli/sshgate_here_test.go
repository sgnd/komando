package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// The server mode (--here, U117): a phone's key on a server, its line
// written by `credential key install --public-key-file` (C372).
var (
	hereKey     = gateKey{network: true, here: true}
	hereReadKey = gateKey{readOnly: true, here: true}
)

// serverHome makes this test's server: the paired user anna's home with
// the files rule a protects, and another user budi in the user database.
func serverHome(t *testing.T) (home string) {
	t.Helper()
	unixOnly(t, "the server mode runs on Unix servers")
	invHome(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(root, "home", "anna")
	budi := filepath.Join(root, "home", "budi")
	for _, d := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, "work"), budi} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{".ssh/authorized_keys", ".profile", "work/notes.txt"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	passwd := filepath.Join(root, "passwd")
	if err := os.WriteFile(passwd, []byte("anna:x:1000:1000::"+home+":/bin/sh\nbudi:x:1001:1001::"+budi+":/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	saved := gatePasswd
	gatePasswd = passwd
	t.Cleanup(func() { gatePasswd = saved })
	return home
}

// serverAnswer is gateCheck's refusal in server mode: its code and message
// ("" when allowed).
func serverAnswer(t *testing.T, line string, key gateKey) (code, msg string) {
	t.Helper()
	req, perr := parseGate(line)
	if perr != nil {
		t.Fatal(perr)
	}
	_, _, e := gateCheck(req.args, key)
	if e == nil {
		return "", ""
	}
	if want := map[bool]int{true: out.ExitRemote, false: out.ExitPolicy}[e.Code == "SSH_GATE_PATH_DENIED"]; e.Exit != want || e.Hint == "" {
		t.Errorf("%q: %+v", line, e)
	}
	return e.Code, e.Message
}

// TestGateServerRules pins rules a, d and f through the gate's own check,
// with the real gate code in a temp home. Each refusal must name its
// reason: a mutant that drops rule a still gets upload refused by rule d,
// but then the message no longer names authorized_keys.
func TestGateServerRules(t *testing.T) {
	serverHome(t)
	for _, line := range []string{
		"komando svc status localhost nginx", "komando svc restart localhost nginx", "komando svc list localhost",
		"komando pkg installed localhost", "komando pkg upgradable localhost", "komando facts localhost",
		"komando fs cat localhost /etc/os-release", "komando fs list localhost ~/work", "komando fs stat localhost work/notes.txt",
		"komando fs cat localhost ~/.profile", // a read of a start file changes nothing
		"komando ssh-gate status -o json", "komando version", "komando svc status localhost nginx --help",
	} {
		if code, msg := serverAnswer(t, line, hereKey); code != "" {
			t.Errorf("%q: refused %s (%s), want it allowed in server mode", line, code, msg)
		}
	}
	// rule a: the gate protects itself, with its own code (probe 5 is the
	// first line)
	for line, word := range map[string]string{
		"komando upload localhost - ~/.ssh/authorized_keys":                 "authorized_keys",
		"komando upload localhost - .ssh/authorized_keys2":                  "authorized_keys2",
		"komando fs write localhost ~/.ssh/authorized_keys --from -":        "authorized_keys",
		"komando fs write localhost .bashrc --from -":                       ".bashrc",
		"komando fs write localhost ~/.zshrc --from -":                      ".zshrc",
		"komando fs mv localhost ~/.ssh ~/old":                              ".ssh",
		"komando fs mv localhost ~ /tmp/x":                                  "holds",
		"komando fs chmod localhost 777 ~/.ssh":                             ".ssh",
		"komando cp - localhost:.profile":                                   ".profile",
		"komando download localhost /etc/hosts --to ~/.ssh/authorized_keys": "authorized_keys", // a read that saves a file
		"komando fs rm localhost " + os.Getenv("KOMANDO_HOME") + "/audit":   "komando's own folder",
	} {
		code, msg := serverAnswer(t, line, hereKey)
		if code != "SSH_GATE_PATH_DENIED" || !strings.Contains(msg, word) {
			t.Errorf("%q: %s %q, want SSH_GATE_PATH_DENIED naming %q", line, code, msg, word)
		}
	}
	for line, word := range map[string]string{
		// rule d: exec is a shell; only the typed commands run
		"komando exec localhost -- id":                 "shell",
		"komando exec localhost --read-only -- id":     "shell",
		"komando job start localhost -- id":            "shell",
		"komando key list":                             "only",
		"komando fs write localhost ~/work/x --from -": "only",
		"komando db query pg 'select 1'":               "only",
		"komando svc status web1 nginx":                "not this server",
		"komando svc stop localhost sshd":              "dangerous",
		"komando pkg rm localhost openssh-server":      "dangerous",
		"komando fs cat localhost /etc/shadow --sudo":  "sudo",
		// rule f: no read of another home, ~/.ssh or komando's own folder
		"komando fs cat localhost ~budi/.bash_history":    "budi",
		"komando fs cat localhost ~/.ssh/id_ed25519":      ".ssh",
		"komando logs localhost --file ~/.ssh/id_ed25519": ".ssh",
	} {
		code, msg := serverAnswer(t, line, hereKey)
		if code != "SSH_GATE_REFUSED" || !strings.Contains(msg, word) {
			t.Errorf("%q: %s %q, want SSH_GATE_REFUSED naming %q", line, code, msg, word)
		}
	}
	if code, _ := serverAnswer(t, "komando svc restart localhost nginx", hereReadKey); code != "SSH_GATE_READ_ONLY" {
		t.Errorf("a read-only key restarts a service: %s", code)
	}
}

// TestGateServerProtectsTheRealSSHFolder: rule a with the home's own
// links: a symlink and a hardlink to authorized_keys, and a dangling
// symlink to authorized_keys2, are refused by what they point at.
func TestGateServerProtectsTheRealSSHFolder(t *testing.T) {
	home := serverHome(t)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for name, mk := range map[string]func(string) error{
		"soft": func(p string) error { return os.Symlink(keys, p) },
		"hard": func(p string) error { return os.Link(keys, p) },
		"next": func(p string) error { return os.Symlink(keys+"2", p) },
		"dir":  func(p string) error { return os.Symlink(filepath.Join(home, ".ssh"), p) },
	} {
		p := filepath.Join(home, "work", name)
		if err := mk(p); err != nil {
			t.Fatal(err)
		}
		target := p
		if name == "dir" {
			target = p + "/authorized_keys"
		}
		if code, msg := serverAnswer(t, "komando upload localhost - "+target, hereKey); code != "SSH_GATE_REFUSED" || !strings.Contains(msg, "no key changes it") {
			t.Errorf("%s: %s %q, want rule a's refusal", name, code, msg)
		}
	}
}

// TestGateServerRunsNothingYet: until the local transport (C549) the
// server mode answers ssh-gate status itself and starts no komando, also
// for a command its rules allow; every answer is audited with here.
func TestGateServerRunsNothingYet(t *testing.T) {
	serverHome(t)
	ran, _, e := gateRun(t, "komando svc status localhost nginx", "--name", "komando-phone-anna", "--here")
	if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "own server yet") {
		t.Errorf("ran %q, %+v", ran, e)
	}
	if a := lastAudit(t); a["here"] != true || a["ok"] != false || a["ssh_gate"] != "komando-phone-anna" {
		t.Errorf("audit %v", a)
	}
	t.Setenv("SSH_ORIGINAL_COMMAND", "komando ssh-gate status -o json")
	t.Setenv("SSH_CONNECTION", "203.0.113.7 51000 10.0.0.2 22")
	data, e := invRun(t, "ssh-gate", "--name", "komando-phone-anna", "--here")
	if e != nil || data["gate"] != true || data["here"] != true || data["name"] != "komando-phone-anna" || data["read_only"] != false || data["shell_access"] != false {
		t.Errorf("status %v %+v", data, e)
	}
	if _, _, e := gateRun(t, "komando list", "--name", "komando-phone-anna", "--here", "--shell-access"); e == nil || e.Code != "USAGE" {
		t.Errorf("--here with --shell-access: %+v", e)
	}
}

// TestGateServerReadsTheCommandAsData pins rule c in server mode: an empty
// command (a plain login) is refused as no shell, a KOMANDO_AGENT= prefix
// is refused (the audit log names a phone's key by its line), and a second
// command, a line break or an expansion is refused before anything else.
// Mutants: parseGate without its empty check (the refusal then says "is
// not komando"), or the server mode taking KOMANDO_AGENT=, turn it red.
func TestGateServerReadsTheCommandAsData(t *testing.T) {
	serverHome(t)
	for line, want := range map[string]string{
		"":                                     "opens no shell",
		"   ":                                  "opens no shell",
		"komando ssh-gate status; id":          "",
		"komando ssh-gate status\nid":          "",
		"komando ssh-gate status $(id)":        "",
		`komando ssh-gate status "$(id)"`:      "",
		"komando ssh-gate status `id`":         "",
		"komando ssh-gate status > ~/.profile": "",
		"KOMANDO_AGENT=other komando ssh-gate status": "KOMANDO_AGENT", // the key does not rename itself
	} {
		ran, _, e := gateRun(t, line, "--name", "komando-phone-anna", "--here")
		code := "SSH_GATE_SYNTAX"
		if want != "" {
			code = "SSH_GATE_REFUSED"
		}
		if ran != nil || e == nil || e.Code != code || !strings.Contains(e.Message, want) {
			t.Errorf("%q: ran %q, %+v, want %s %q", line, ran, e, code, want)
		}
	}
}

// TestGateServerSystemLog pins rule f's copy: in server mode every record
// also goes to the system log, which the paired user cannot change.
// Mutant: dropping the gateSystemLog call turns it red.
func TestGateServerSystemLog(t *testing.T) {
	serverHome(t)
	var got []map[string]any
	saved := gateSystemLog
	gateSystemLog = func(rec map[string]any) { got = append(got, rec) }
	t.Cleanup(func() { gateSystemLog = saved })
	_, _, _ = gateRun(t, "komando exec localhost -- id", "--name", "komando-phone-anna", "--here")
	if len(got) != 1 || got[0]["ssh_gate"] != "komando-phone-anna" || got[0]["blocked"] != "SSH_GATE_REFUSED" {
		t.Errorf("system log %v", got)
	}
	_, _, _ = gateRun(t, "komando list", "--name", "phone")
	if len(got) != 1 {
		t.Errorf("a computer-side key wrote to the system log: %v", got)
	}
}
