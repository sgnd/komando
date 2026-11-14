package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// O9: a server's own env (host edit --env API_TOKEN=secret:tok) went into
// every AI agent's exec, where `printenv API_TOKEN | rev` reads it back
// unmasked. For an agent the vault values of the host's env are left out
// (with a warning) unless it adds --yes and the person allows it.
func TestHostEnvSecretNeedsAPersonForAnAgent(t *testing.T) {
	invHome(t)
	if err := vault.Set(store.Save, "tok", "host-env-token-5531"); err != nil {
		t.Fatal(err)
	}
	h := &store.Host{Name: "web1", Address: "10.0.0.1", User: "deploy", Env: map[string]string{"API_TOKEN": "secret:tok", "REGION": "eu"}}
	c := &sshx.Client{Host: h}
	sends := func() (bool, string) {
		t.Helper()
		cmd, _, err := sshx.BuildCommand(c, sshx.RunRequest{Command: "printenv API_TOKEN"})
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(cmd, "read -r API_TOKEN"), cmd
	}
	t.Cleanup(func() { tcl.flags.yes = false })

	// a person or a script: as before
	noAgent(t)
	if ok, cmd := sends(); !ok || !strings.Contains(cmd, "REGION") {
		t.Fatalf("a person's command lost the env: %s", cmd)
	}

	// an agent without --yes: left out, with a warning; plain values stay
	n := asAgent(t, true, true)
	tcl.out.Reset()
	tcl.flags.yes = false
	if err := guardHostEnv(tcl, []*store.Host{h}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, cmd := sends(); ok || !strings.Contains(cmd, "REGION") {
		t.Fatalf("an agent's command got the host's vault env: %s", cmd)
	}
	if *n != 0 {
		t.Fatal("asked without --yes")
	}
	// the command's own --env names the variable: not the host's to send
	if err := guardHostEnv(tcl, []*store.Host{h}, map[string]string{"API_TOKEN": "x"}); err != nil {
		t.Fatal(err)
	}

	// an agent with --yes whom the person refuses: stopped
	asAgent(t, false, true)
	tcl.flags.yes = true
	if err := guardHostEnv(tcl, []*store.Host{h}, nil); toErr(err).Code != "SECRET_DESTINATION" {
		t.Fatalf("refused: %v", err)
	}
	if ok, _ := sends(); ok {
		t.Fatal("sent after a no")
	}

	// an agent with --yes whom the person allows: sent, asked once
	n = asAgent(t, true, true)
	tcl.flags.yes = true
	if err := guardHostEnv(tcl, []*store.Host{h}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sends(); !ok || *n != 1 {
		t.Fatalf("after the yes: sent=%v, asked %d times", ok, *n)
	}
}
