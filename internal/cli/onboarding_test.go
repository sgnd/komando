package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/vault"
)

// --ask-password: a person types the password once while adding the
// server; it lands in the vault as secret:NAME-pass. Agents and scripts are
// never asked.
func TestAskPassword(t *testing.T) {
	invHome(t)
	// a script: no terminal
	e := wantCode(t, "NEEDS_TERMINAL", "host", "add", "vps1", "root@10.0.0.20", "--ask-password")
	if !strings.Contains(e.Hint, "komando secret set vps1-pass") {
		t.Errorf("script hint: %q", e.Hint)
	}
	// an agent
	asAgent(t, false, false)
	e = wantCode(t, "NEEDS_PERSON", "host", "add", "vps1", "root@10.0.0.20", "--ask-password")
	if !strings.Contains(e.Hint, "ask the user to run `komando") || !strings.Contains(e.Hint, "never ask for a password in the chat") { // the command line is tcl.args
		t.Errorf("agent hint: %q", e.Hint)
	}
	noAgent(t)

	// a person
	saved, savedInteractive := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = saved, savedInteractive })
	tcl.terminal = true
	asked := 0
	readPassword = func(_ *call, label string) (string, error) {
		asked++
		if !strings.Contains(label, "vps1") {
			t.Errorf("question: %q", label)
		}
		return "Typed-Pass-1", nil
	}
	d := mustRun(t, "host", "add", "vps1", "root@10.0.0.20", "--ask-password")
	if d["password_ref"] != "secret:vps1-pass" || d["next"] != "komando test vps1" || asked != 1 {
		t.Errorf("host add --ask-password: %v (asked %d)", d, asked)
	}
	if v, err := vault.Get("vps1-pass"); err != nil || v != "Typed-Pass-1" {
		t.Errorf("vault: %q %v", v, err)
	}
	wantCode(t, "USAGE", "host", "edit", "vps1", "--ask-password", "--password-ref", "env:X")
	// a new password for the same server replaces its own secret
	readPassword = func(*call, string) (string, error) { return "Typed-Pass-2", nil }
	mustRun(t, "host", "edit", "vps1", "--ask-password")
	if v, _ := vault.Get("vps1-pass"); v != "Typed-Pass-2" {
		t.Errorf("edit did not store the new password: %q", v)
	}
	// a secret of that name that another server uses is never replaced
	mustRun(t, "host", "add", "other", "root@10.0.0.21", "--password-ref", "secret:web9-pass")
	setSecret(t, "web9-pass", "keep-me")
	if e := wantCode(t, "SECRET_EXISTS", "host", "add", "web9", "root@10.0.0.22", "--ask-password"); !strings.Contains(e.Message, "host other") {
		t.Errorf("collision: %+v", e)
	}
	if v, _ := vault.Get("web9-pass"); v != "keep-me" {
		t.Error("the other server's secret was replaced")
	}
	// a failed add takes back the secret it made
	if _, e := invRun(t, "host", "add", "web8", "root@10.0.0.30", "--ask-password", "--via", "no-such-bastion"); e == nil {
		t.Fatal("an unknown --via: the add must fail")
	}
	if _, err := vault.Get("web8-pass"); err == nil {
		t.Error("a failed add left its new secret in the vault")
	}
	// conns too
	d = mustRun(t, "conn", "add", "app-db", "postgres://app@10.0.0.5/app", "--ask-password")
	if d["password_ref"] != "secret:app-db-pass" {
		t.Errorf("conn add --ask-password: %v", d)
	}
	// a dry run asks nothing and stores nothing
	asked = 0
	readPassword = func(*call, string) (string, error) { asked++; return "x", nil }
	mustRun(t, "host", "add", "dry1", "root@10.0.0.40", "--ask-password", "--dry-run")
	if _, err := vault.Get("dry1-pass"); err == nil || asked != 0 {
		t.Errorf("dry run asked %d times or stored the secret", asked)
	}
}

// A reference to a secret that is not in the vault yet is said when it is
// made, and add says what to run next.
func TestAddWarnsAndSaysNext(t *testing.T) {
	invHome(t)
	d := mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--password-ref", "secret:web1-pas")
	if !strings.Contains(fmtAny(d["warnings"]), "secret web1-pas is not in the vault yet: store it with `komando secret set web1-pas`") {
		t.Errorf("host add: %v", d)
	}
	d = mustRun(t, "conn", "edit", mustConn(t), "--password-ref", "secret:db-pas")
	if !strings.Contains(fmtAny(d["warnings"]), "secret db-pas is not in the vault yet") {
		t.Errorf("conn edit: %v", d)
	}
	text := renderedText(t, map[string]any{"name": "web1", "action": "added", "address": "10.0.0.1", "next": "komando test web1"})
	if strings.Contains(text, "next") || !strings.HasPrefix(text, "added web1\n") {
		t.Errorf("text names the next command on stdout (it is data.next and the Next: line on stderr): %q", text)
	}
	if d := mustRun(t, "host", "add", "web2", "u@10.0.0.2"); d["next"] != "komando test web2" {
		t.Errorf("data.next: %v", d["next"])
	}
}

// Removing what used a secret says the secret is left, with the command to
// remove it; komando never removes it by itself.
func TestRmNamesUnusedSecrets(t *testing.T) {
	invHome(t)
	setSecret(t, "db-pass", "x")
	setSecret(t, "shared-pass", "y")
	mustRun(t, "conn", "add", "db1", "postgres://app@10.0.0.5/app", "--password-ref", "secret:db-pass")
	mustRun(t, "conn", "add", "db2", "postgres://app@10.0.0.6/app", "--password-ref", "secret:shared-pass")
	mustRun(t, "host", "add", "web1", "u@10.0.0.1", "--password-ref", "secret:shared-pass")
	d := mustRun(t, "conn", "rm", "db1", "db2")
	if fmtAny(d["secrets_unused"]) != "[db-pass]" {
		t.Errorf("only db-pass is left unused: %v", d)
	}
	if _, err := vault.Get("db-pass"); err != nil {
		t.Error("komando removed the secret by itself")
	}
	if s := (rmResult{Removed: []string{"db1"}, SecretsUnused: []string{"db-pass"}}).Text(); !strings.Contains(s, "removed db1\ndb-pass is no longer used: `komando secret rm db-pass`") {
		t.Errorf("text: %q", s)
	}
}

// What people read after a change says what happened first, in words.
func TestChangeTextInWords(t *testing.T) {
	added := true
	for got, want := range map[string]string{
		policyChange{Custom: []string{"a", "b"}, Added: &added, pattern: "b"}.denied(tcl).TextFor(tcl.out):                         "added the deny rule b as " + policy.CustomID("b") + " (2 custom rules now)\n",
		policyChange{Custom: []string{"a"}, Removed: "b"}.TextFor(tcl.out):                                                         "removed the deny rule b (1 custom rule left)\n",
		exportResult{File: "f.json", Hosts: 2, Conns: 1, SecretsNeeded: []string{"p"}}.Text():                                      "saved 2 servers, 1 conn to f.json (no passwords)\nset again on the other computer: p (`komando secret set NAME`)\n",
		renderedText(t, map[string]any{"name": "app-db-pass", "action": "stored", "replaced": false, "ref": "secret:app-db-pass"}): "stored app-db-pass\n  ref: secret:app-db-pass\n",
	} {
		if got != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
	}
}

func fmtAny(v any) string { return fmt.Sprint(v) }

// mustConn adds a conn for a test and returns its name.
func mustConn(t *testing.T) string {
	t.Helper()
	mustRun(t, "conn", "add", "db", "postgres://app@10.0.0.9/app")
	return "db"
}

// renderedText is what a person sees for data.
func renderedText(t *testing.T, data any) string {
	t.Helper()
	var buf bytes.Buffer
	p := &out.Printer{Format: "text", W: &buf}
	p.Print("test", data, nil)
	return buf.String()
}
