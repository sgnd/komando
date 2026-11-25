package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// An import that carries a conn's password stores it as NAME-pass. With
// --overwrite an AI agent could so replace a secret on the way to a
// login-ask server (here the key of the VPN it is reached through) and
// lead the typed password to its own network: NEEDS_PERSON, as for
// secret set, and the secret keeps its value.
func TestLoginAskImportKeepsTheSecretOnTheWay(t *testing.T) {
	secretHome(t)
	t.Setenv("TSKEY", "tskey-the-persons")
	mustRun(t, "secret", "set", "corp-pass", "--from-env", "TSKEY")
	mustRun(t, "vpn", "add", "ts", "tailscale", "--password-ref", "credential:corp-pass")
	mustRun(t, "host", "add", "web1", "u@100.64.0.5", "--login", "ask", "--via", "ts")
	setCallerEnv(t, "CLAUDECODE", "1")
	env := writeTemp(t, ".env", "CORP_URL=postgres://app:tskey-the-agents@127.0.0.1:5432/app\n")
	e := wantCode(t, "NEEDS_PERSON", "import", "env", env, "--overwrite")
	if !strings.Contains(e.Message, "corp-pass") || !strings.Contains(e.Message, "server web1") {
		t.Errorf("%+v", e)
	}
	if v, _ := vault.Get("corp-pass"); v != "tskey-the-persons" {
		t.Errorf("the VPN's key was replaced: %q", v)
	}
}

// default_user is also the account of a jump server with no user of its
// own: on the way to a login-ask server it is part of where the typed
// password goes, so an agent's change of it gets NEEDS_PERSON, as
// host edit --user on that jump server does.
func TestLoginAskDefaultUserOfAJumpServer(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "bastion", "10.0.0.1")
	mustRun(t, "host", "add", "web1", "u@10.0.0.5", "--login", "ask", "--via", "bastion")
	setCallerEnv(t, "CLAUDECODE", "1")
	wantCode(t, "NEEDS_PERSON", "host", "edit", "bastion", "--user", "root")
	e := wantCode(t, "NEEDS_PERSON", "config", "set", "default_user", "root")
	if !strings.Contains(e.Message, "bastion") || !strings.Contains(e.Message, "web1") {
		t.Errorf("%+v", e)
	}
}

// tunnel serve reads what tunnel start wrote in one order: its ticket,
// then the typed passwords. Without a ticket it stops, whatever follows.
func TestLoginAskServeReadsTicketThenLogins(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.5", "--login", "ask") // the store the ticket's key comes from
	saved, savedIn := tcl.args, tcl.stdin
	t.Cleanup(func() { tcl.args, tcl.stdin = saved, savedIn; resetApproval() })
	cmd := []string{"tunnel", "serve", "t1", loginsStdinFlag}
	tcl.args = append([]string{"komando"}, cmd...)
	logins, _ := io.ReadAll(loginsInput(map[string]string{"web1": "typed-Pa55"}))
	line, err := ticketLine(cmd)
	if err != nil {
		t.Fatal(err)
	}
	tcl.stdin = strings.NewReader(line + string(logins))
	if _, err := serveState(tcl, true, false); err != nil {
		t.Fatalf("ticket then passwords: %v", err)
	}
	q := sshx.LoginAsk{Host: &store.Host{Name: "web1", Login: store.LoginAsk}, User: "u", Addr: "10.0.0.5:22"}
	if pw, _, err := tcl.loginPassword(q); err != nil || pw != "typed-Pa55" {
		t.Errorf("web1: %q %v", pw, err)
	}
	// run by hand: no ticket, nothing at all, or a ticket made for a
	// tunnel serve without the passwords flag
	other, _ := ticketLine(cmd[:3])
	for _, in := range []string{string(logins), "", other + string(logins)} {
		tcl.stdin = strings.NewReader(in)
		if _, err := serveState(tcl, true, false); err == nil || toErr(err).Code != "NEEDS_PERSON" {
			t.Errorf("stdin %q: %v", in, err)
		}
	}
}

// The same for a secret that is not there yet: a VPN on the way names
// it, so the import that would make it gives the VPN the agent's key.
func TestLoginAskImportCannotMakeTheSecretOnTheWay(t *testing.T) {
	secretHome(t)
	mustRun(t, "vpn", "add", "ts", "tailscale", "--password-ref", "credential:corp-pass")
	mustRun(t, "host", "add", "web1", "u@100.64.0.5", "--login", "ask", "--via", "ts")
	setCallerEnv(t, "CLAUDECODE", "1")
	env := writeTemp(t, ".env", "CORP_URL=postgres://app:tskey-the-agents@127.0.0.1:5432/app\n")
	wantCode(t, "NEEDS_PERSON", "import", "env", env)
	if v, err := vault.Get("corp-pass"); err == nil {
		t.Errorf("the import made the VPN's key: %q", v)
	}
}
