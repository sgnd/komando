package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// shellKey is a key whose line has --shell-access, on a call sshd gave a terminal.
var shellKey = gateKey{network: true, shellAccess: true, tty: true}

// shellInventory is gateInventory with the servers a shell is refused on:
// prod is protected, prod-alias is prod under another name, win and winrm
// are Windows servers.
func shellInventory(t *testing.T) {
	t.Helper()
	gateInventory(t)
	err := store.Update(store.Save(), func(st *store.State) error {
		for n, h := range map[string]store.Host{
			"prod": {Address: "10.0.0.20", Protected: true}, "prod-alias": {Address: "10.0.0.20"},
			"win": {Address: "10.0.0.30", OS: store.OSWindows}, "winrm": {Address: "10.0.0.31", Transport: store.TransportWinRM},
		} {
			h.Name, h.User = n, "u"
			st.Hosts[n] = &h
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// shellAnswer is the gate's answer for a shell key: nil when allowed.
func shellAnswer(t *testing.T, line string, key gateKey) *out.Error {
	t.Helper()
	words, err := gateWords(line)
	if err != nil {
		t.Fatal(err)
	}
	_, _, e := gateCheck(words, key)
	if e != nil && (e.Exit != out.ExitPolicy || e.Hint == "") {
		t.Errorf("%q: %+v", line, e)
	}
	return e
}

// wantShellRefused checks that each line is refused for key with
// SSH_GATE_REFUSED and a message that holds why.
func wantShellRefused(t *testing.T, key gateKey, why string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		e := shellAnswer(t, line, key)
		if e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, why) {
			t.Errorf("%q: %+v, want SSH_GATE_REFUSED saying %q", line, e, why)
		}
	}
}

// shellTerminal plays what sshd gave the gate's call: SSH_TTY as tty, and
// stdin and stderr a terminal when terminal is set.
func shellTerminal(t *testing.T, tty string, terminal bool) {
	t.Helper()
	t.Setenv("SSH_TTY", tty)
	saved := tcl.terminal
	t.Cleanup(func() { tcl.terminal = saved })
	tcl.terminal = terminal
}

func TestGateShellAllowed(t *testing.T) {
	invHome(t)
	shellInventory(t)
	for _, line := range []string{"host ssh shell web", "host ssh shell bastion", "host ssh shell behind"} {
		if e := shellAnswer(t, line, shellKey); e != nil {
			t.Errorf("%q: %+v", line, e)
		}
	}
}

// The gate opens a shell key's shell in its own process, as the key: no
// komando of its own is started for it, and the session is in the audit log
// after the gate's own record.
func TestGateShellRunsInGate(t *testing.T) {
	conn, _ := gateSessionLab(t)
	t.Cleanup(resetApproval) // the gate's call takes the key as its caller
	var dialed string
	shellDial = func(_ *call, _ context.Context, _ *store.State, h *store.Host, fn func(shellConn) error) error {
		dialed = h.Name
		return fn(conn)
	}
	shellTerminal(t, "/dev/pts/3", true)
	conn.end <- nil
	ran, _, e := gateRun(t, "KOMANDO_AGENT=Komando komando host ssh shell web", "--name", "ops", "--shell-access")
	if ran != nil || e != nil {
		t.Fatalf("ran %q, error %+v; want the shell in the gate", ran, e)
	}
	if dialed != "web" {
		t.Errorf("dialed %q, want web", dialed)
	}
	if tcl.interactive() {
		t.Errorf("the gate's call would ask a question on the key's terminal")
	}
	if !tcl.gated() {
		t.Errorf("the shell did not run as the key")
	}
	var gate map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) == nil && r["command"] == "ssh-gate" {
			gate = r
		}
	}
	for k, want := range map[string]any{"ok": true, "runs": "host ssh shell", "ssh_gate": "ops", "shell_access": true, "read_only": false} {
		if gate[k] != want {
			t.Errorf("gate record %s = %v, want %v", k, gate[k], want)
		}
	}
	recs := sessionRecords(t)
	if len(recs) != 2 {
		t.Fatalf("session records %v, want a start and an end", recs)
	}
	wantRecord(t, recs[1], map[string]any{"session": "end", "end": "exit", "ssh_gate": "ops", "agent": "ssh-gate key ops", "hosts": []string{"web"}})
}

// A shell on a protected server can change anything, and no key has the
// person on this computer that --yes needs there.
func TestGateShellProtected(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "protected", "host ssh shell prod", "host ssh shell prod-alias")
}

// A Windows server gives its own shell, cmd or PowerShell, which no rule
// here was written for.
func TestGateShellWindows(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "Windows", "host ssh shell win", "host ssh shell winrm")
}

// A server that is the komando computer itself would be a shell here.
func TestGateShellThisComputer(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "on this computer", "host ssh shell me", "host ssh shell lh", "host ssh shell v6", "host ssh shell short", "host ssh shell any",
		"host ssh shell named", "host ssh shell loop", "host ssh shell vpnd")
}

// Only `komando host ssh shell SERVER` as such: no other word, no flag, no alias,
// nothing before or after.
func TestGateShellExtraArgs(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "komando host ssh shell SERVER", "host ssh shell", "host ssh shell web uptime", "host ssh shell web web", "host ssh shell web --",
		"host ssh shell -- web", "host ssh shell web --dry-run", "--dry-run host ssh shell web", "host ssh shell web -o json", "-o json host ssh shell web",
		"host ssh shell --help", "host ssh shell web --help", "host ssh shell web --yes", "host ssh shell --yes web", "host ssh shell web --reveal",
		"host ssh shell web --allow-dangerous", "host ssh shell web --timeout 1h", "host ssh shell -web")
}

// The server must be one in the list, named as it is written there: no ad
// hoc user@host or address, no selector, no other spelling.
func TestGateShellListedServerOnly(t *testing.T) {
	invHome(t)
	shellInventory(t)
	// names a selector reads its own way, as a store from elsewhere may hold
	err := store.Update(store.Save(), func(st *store.State) error {
		for _, n := range []string{"all", "os:linux", "tag:x"} {
			st.Hosts[n] = &store.Host{Name: n, User: "u", Address: "10.0.0.40"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantShellRefused(t, shellKey, "no server in your list", "host ssh shell u@10.0.0.5", "host ssh shell 10.0.0.5", "host ssh shell '[2001:db8::1]'",
		"host ssh shell @prod", "host ssh shell 'web*'", "host ssh shell all", "host ssh shell web,prod", "host ssh shell '!prod'", "host ssh shell WEB", "host ssh shell pg",
		"host ssh shell k8s", "host ssh shell office", "host ssh shell nothing", "host ssh shell ''", "host ssh shell 'web '", "host ssh shell tag:x", "host ssh shell os:linux")
}

func TestGateShellDBShell(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "needs a person at a terminal", "db shell pg", "db shell pg --write")
}

func TestGateShellClusterShell(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "needs a person at a terminal", "cluster shell k8s pod/x", "cluster shell k8s pod/x -- sh")
}

// The shell needs the terminal sshd gives a key that asks for one (ssh
// -t): SSH_TTY alone, which a client may send, is not enough, nor a
// terminal without SSH_TTY.
func TestSSHGateShellNoPty(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, gateKey{network: true, shellAccess: true}, "terminal", "host ssh shell web")
	for _, c := range []struct {
		name     string
		tty      string
		terminal bool
	}{
		{"no SSH_TTY", "", true},
		{"no terminal", "/dev/pts/3", false},
		{"neither", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			shellTerminal(t, c.tty, c.terminal)
			ran, _, e := gateRun(t, "komando host ssh shell web", "--name", "ops", "--shell-access")
			if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "terminal") {
				t.Fatalf("ran %q, error %+v", ran, e)
			}
			if a := lastAudit(t); a["ok"] != false || a["runs"] != "host ssh shell" || a["shell_access"] != true {
				t.Errorf("audit %v", a)
			}
		})
	}
}

// ssh -t HOST with no command is a login: the gate opens none, for a
// --shell-access key either.
func TestSSHGateShellNeedsCommand(t *testing.T) {
	invHome(t)
	shellTerminal(t, "/dev/pts/3", true)
	ran, _, e := gateRun(t, "", "--name", "ops", "--shell-access")
	if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" {
		t.Errorf("ran %q, error %+v", ran, e)
	}
}

// A line with --shell-access and --read-only is a mistake: the gate runs nothing
// for it.
func TestSSHGateShellReadOnlyLine(t *testing.T) {
	invHome(t)
	shellTerminal(t, "/dev/pts/3", true)
	for _, line := range []string{"komando host ssh shell web", "komando list"} {
		if ran, _, e := gateRun(t, line, "--name", "ops", "--read-only", "--shell-access"); ran != nil || e == nil || e.Code != "USAGE" {
			t.Errorf("%q: ran %q, error %+v", line, ran, e)
		}
	}
}

// --shell-access adds the shell and nothing else: every other command gets the
// answer a key without it gets.
func TestGateShellKeyOtherwiseFull(t *testing.T) {
	invHome(t)
	shellInventory(t)
	root := newRoot(tcl)
	n := 0
	for _, c := range allCommands(root) {
		if !c.HasParent() {
			continue
		}
		line := append(strings.Fields(strings.TrimPrefix(c.CommandPath(), "komando")), "web")
		name, _, full := gateCheck(line, fullKey)
		if isHostShell(name) {
			continue
		}
		_, _, sh := gateCheck(line, shellKey)
		if gateErrText(full) != gateErrText(sh) {
			t.Errorf("%q: %q with --shell-access, %q without", line, gateErrText(sh), gateErrText(full))
		}
		n++
	}
	if n < 200 {
		t.Fatalf("only %d lines compared", n)
	}
}

// gateErrText is a refusal as one string to compare ("" when allowed).
func gateErrText(e *out.Error) string {
	if e == nil {
		return ""
	}
	return e.Code + ": " + e.Message
}

// The komando a key runs never asks its key anything, also when sshd gave
// the call a terminal, and `komando host ssh shell` refuses it: a key's shell is
// opened by the gate alone. Variables that look like the gate's change
// nothing, whoever sets them.
func TestGateCallNeverInteractive(t *testing.T) {
	for _, c := range []struct {
		name, gate, tty string
		terminal        bool
	}{
		{"the gate's three variables and a terminal, not from the gate", "ops", "/dev/pts/3", true},
		{"a key's call without a terminal", "ops", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			setCallerEnv(t, gateEnv, c.gate)
			t.Setenv("KOMANDO_GATE_SHELL", "1")
			shellTerminal(t, c.tty, c.terminal)
			if tcl.interactive() {
				t.Fatal("a key's call is interactive")
			}
			if err := runShell(tcl, context.Background(), "web"); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
				t.Errorf("shell: %v, want NEEDS_TERMINAL", err)
			}
		})
	}
}

// The gate checks the server again just before it opens the shell, and
// refuses where a person would be asked.
func TestGateRunShellRechecks(t *testing.T) {
	gateSessionLab(t)
	t.Cleanup(resetApproval)
	shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
		t.Error("it connected")
		return nil
	}
	for server, why := range map[string]string{"prod": "protected", "prod-alias": "protected", "win": "Windows", "u@10.0.0.5": "no server in your list"} {
		err := gateRunShell(tcl, context.Background(), "ops", server)
		if e := toErr(err); e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, why) {
			t.Errorf("%s: %v, want SSH_GATE_REFUSED saying %q", server, err, why)
		}
	}
}

// While a deny rule of your own is set, no key opens a shell on any server:
// komando does not see what is typed in one, so it would get past the rule.
func TestGateShellExtraDenyPatterns(t *testing.T) {
	denyRule := func(t *testing.T) {
		t.Helper()
		err := store.Update(store.Save(), func(st *store.State) error {
			st.Settings.ExtraDenyPattern = []string{`kubectl\s+delete`}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("the gate", func(t *testing.T) {
		invHome(t)
		shellInventory(t)
		denyRule(t)
		wantShellRefused(t, shellKey, "deny rules of your own", "host ssh shell web", "host ssh shell bastion", "host ssh shell behind")
		e := shellAnswer(t, "host ssh shell web", shellKey)
		if e == nil || !strings.Contains(e.Hint, "komando host ssh exec") {
			t.Errorf("hint %+v, want single commands, which the rules check", e)
		}
	})
	t.Run("just before the shell opens", func(t *testing.T) {
		gateSessionLab(t)
		t.Cleanup(resetApproval)
		denyRule(t)
		shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
			t.Error("it connected")
			return nil
		}
		err := gateRunShell(tcl, context.Background(), "ops", "web")
		if e := toErr(err); e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "deny rules of your own") {
			t.Errorf("shell: %v, want SSH_GATE_REFUSED", err)
		}
	})
}

// ssh-gate is for sshd: an AI agent on this computer that starts it itself
// is refused, for the shell and every other command, and the refusal is in
// the audit log.
func TestSSHGateAgentCaller(t *testing.T) {
	for _, line := range []string{"komando host ssh shell web", "komando list"} {
		t.Run(line, func(t *testing.T) {
			gateSessionLab(t)
			shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
				t.Error("it connected")
				return nil
			}
			shellTerminal(t, "/dev/pts/3", true)
			setCallerEnv(t, "CLAUDECODE", "1")
			ran, _, e := gateRun(t, line, "--name", "ops", "--shell-access")
			if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "AI agent") {
				t.Fatalf("ran %q, error %+v; want SSH_GATE_REFUSED for an AI agent", ran, e)
			}
			if a := lastAudit(t); a["ok"] != false || a["blocked"] != "SSH_GATE_REFUSED" {
				t.Errorf("audit %v", a)
			}
		})
	}
}
