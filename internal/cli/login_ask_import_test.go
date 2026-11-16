package cli

import (
	"strings"
	"testing"

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
	mustRun(t, "vpn", "add", "ts", "tailscale", "--password-ref", "secret:corp-pass")
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
