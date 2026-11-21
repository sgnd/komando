package cli

import (
	"context"
	"slices"
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
	for _, line := range []string{"shell web", "shell bastion", "shell behind"} {
		if e := shellAnswer(t, line, shellKey); e != nil {
			t.Errorf("%q: %+v", line, e)
		}
	}
	shellTerminal(t, "/dev/pts/3", true)
	ran, env, e := gateRun(t, "KOMANDO_AGENT=Komando komando shell web", "--name", "ops", "--shell-access")
	if !slices.Equal(ran, []string{"komando", "shell", "web"}) {
		t.Fatalf("ran %q, error %+v", ran, e)
	}
	if !slices.Contains(env, "KOMANDO_SSH_GATE=ops") || !slices.Contains(env, "KOMANDO_NO_DIALOG=1") {
		t.Errorf("env lacks the gate's variables")
	}
	if tcl.interactive() {
		t.Errorf("the gate's own call would ask a question on the key's terminal")
	}
	a := lastAudit(t)
	for k, want := range map[string]any{"ok": true, "runs": "shell", "ssh_gate": "ops", "shell_access": true, "read_only": false} {
		if a[k] != want {
			t.Errorf("audit %s = %v, want %v", k, a[k], want)
		}
	}
}

// A shell on a protected server can change anything, and no key has the
// person on this computer that --yes needs there.
func TestGateShellProtected(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "protected", "shell prod", "shell prod-alias")
}

// A Windows server gives its own shell, cmd or PowerShell, which no rule
// here was written for.
func TestGateShellWindows(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "Windows", "shell win", "shell winrm")
}

// A server that is the komando computer itself would be a shell here.
func TestGateShellThisComputer(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "on this computer", "shell me", "shell lh", "shell v6", "shell short", "shell any",
		"shell named", "shell loop", "shell vpnd")
}

// Only `komando shell SERVER` as such: no other word, no flag, no alias,
// nothing before or after.
func TestGateShellExtraArgs(t *testing.T) {
	invHome(t)
	shellInventory(t)
	wantShellRefused(t, shellKey, "komando shell SERVER", "shell", "shell web uptime", "shell web web", "shell web --",
		"shell -- web", "shell web --dry-run", "--dry-run shell web", "shell web -o json", "-o json shell web",
		"shell --help", "shell web --help", "shell web --yes", "shell --yes web", "shell web --reveal",
		"shell web --allow-dangerous", "shell web --timeout 1h", "ssh web", "connect web", "shell -web")
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
	wantShellRefused(t, shellKey, "no server in your list", "shell u@10.0.0.5", "shell 10.0.0.5", "shell '[2001:db8::1]'",
		"shell @prod", "shell 'web*'", "shell all", "shell web,prod", "shell '!prod'", "shell WEB", "shell pg",
		"shell k8s", "shell office", "shell nothing", "shell ''", "shell 'web '", "shell tag:x", "shell os:linux")
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
	wantShellRefused(t, gateKey{network: true, shellAccess: true}, "terminal", "shell web")
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
			ran, _, e := gateRun(t, "komando shell web", "--name", "ops", "--shell-access")
			if ran != nil || e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "terminal") {
				t.Fatalf("ran %q, error %+v", ran, e)
			}
			if a := lastAudit(t); a["ok"] != false || a["runs"] != "shell" || a["shell_access"] != true {
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
	for _, line := range []string{"komando shell web", "komando list"} {
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
		if name == "shell" {
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

// The marker that lets the key's komando open the shell comes from the gate
// only: one the key's connection brings (AcceptEnv) is dropped, and the gate
// sets it for a shell key's `komando shell SERVER` with sshd's terminal alone.
func TestGateShellMarkerFromGateOnly(t *testing.T) {
	for _, c := range []struct {
		name, line string
		args, want []string
	}{
		{"a shell key's shell", "komando shell web", []string{"--name", "ops", "--shell-access"}, []string{gateShellEnv + "=1"}},
		{"a shell key's other command", "komando list", []string{"--name", "ops", "--shell-access"}, nil},
		{"a full key", "komando list", []string{"--name", "phone"}, nil},
		{"a read key", "komando list", []string{"--name", "ro", "--read-only"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			invHome(t)
			shellInventory(t)
			shellTerminal(t, "/dev/pts/3", true)
			t.Setenv(gateShellEnv, "1") // sent by the client
			ran, env, e := gateRun(t, c.line, c.args...)
			if ran == nil {
				t.Fatalf("nothing ran: %+v", e)
			}
			var got []string
			for _, kv := range env {
				if strings.HasPrefix(kv, gateShellEnv+"=") {
					got = append(got, kv)
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("markers %q, want %q", got, c.want)
			}
		})
	}
}

// The komando a key runs never asks its key anything, also when sshd gave
// the call a terminal. It opens the shell only with the gate's marker, a
// key's call and sshd's terminal: without any one of them it is refused.
func TestGateCallNeverInteractive(t *testing.T) {
	for _, c := range []struct {
		name, gate, marker, tty string
		terminal                bool
	}{
		{"no marker", "ops", "", "/dev/pts/3", true},
		{"marker without SSH_TTY", "ops", "1", "", true},
		{"marker without a terminal", "ops", "1", "/dev/pts/3", false},
		{"marker of another value", "ops", "yes", "/dev/pts/3", true},
		{"marker for an agent that is no key", "", "1", "/dev/pts/3", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.gate != "" {
				setCallerEnv(t, gateEnv, c.gate)
			} else {
				setCallerEnv(t, "CLAUDECODE", "1")
			}
			t.Setenv(gateShellEnv, c.marker)
			shellTerminal(t, c.tty, c.terminal)
			if tcl.interactive() {
				t.Fatal("a key's or an agent's call is interactive")
			}
			if err := runShell(tcl, context.Background(), "web"); err == nil || toErr(err).Code != "NEEDS_TERMINAL" {
				t.Errorf("shell: %v, want NEEDS_TERMINAL", err)
			}
		})
	}
}

// With the gate's marker, a key's call and sshd's terminal, the shell opens,
// and the call still asks nothing.
func TestGateShellMarkerOpens(t *testing.T) {
	conn, _ := gateSessionLab(t)
	t.Setenv(gateShellEnv, "1")
	shellTerminal(t, "/dev/pts/3", true)
	conn.end <- nil
	if err := runShell(tcl, context.Background(), "web"); err != nil {
		t.Fatalf("shell: %v", err)
	}
	if tcl.interactive() {
		t.Error("the key's call became interactive")
	}
	if recs := sessionRecords(t); len(recs) != 2 {
		t.Errorf("session records %v, want a start and an end", recs)
	}
}

// The shell the gate ran checks the server again, and refuses where a
// person would be asked.
func TestGateShellMarkerRechecks(t *testing.T) {
	gateSessionLab(t)
	t.Setenv(gateShellEnv, "1")
	shellTerminal(t, "/dev/pts/3", true)
	shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
		t.Error("it connected")
		return nil
	}
	for server, why := range map[string]string{"prod": "protected", "prod-alias": "protected", "win": "Windows", "u@10.0.0.5": "no server in your list"} {
		err := runShell(tcl, context.Background(), server)
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
		wantShellRefused(t, shellKey, "deny rules of your own", "shell web", "shell bastion", "shell behind")
		e := shellAnswer(t, "shell web", shellKey)
		if e == nil || !strings.Contains(e.Hint, "komando exec") {
			t.Errorf("hint %+v, want single commands, which the rules check", e)
		}
	})
	t.Run("the shell the gate ran", func(t *testing.T) {
		gateSessionLab(t)
		denyRule(t)
		t.Setenv(gateShellEnv, "1")
		shellTerminal(t, "/dev/pts/3", true)
		shellDial = func(*call, context.Context, *store.State, *store.Host, func(shellConn) error) error {
			t.Error("it connected")
			return nil
		}
		err := runShell(tcl, context.Background(), "web")
		if e := toErr(err); e == nil || e.Code != "SSH_GATE_REFUSED" || !strings.Contains(e.Message, "deny rules of your own") {
			t.Errorf("shell: %v, want SSH_GATE_REFUSED", err)
		}
	})
}
