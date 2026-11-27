package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
)

// A key pinned on first use is in the audit log with its fingerprint.
func TestPinnedKeyIsAudited(t *testing.T) {
	invHome(t)
	sshx.HostKeyPinned(withCall(context.Background(), tcl), sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	b := []byte(auditText(t))
	for _, want := range []string{`"event":"host.key-pinned"`, `"hosts":["web1"]`, `"fingerprint":"SHA256:abc"`, `"key_type":"ssh-ed25519"`, `"first_use":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit record %s has no %s", b, want)
		}
	}
}

// The first connection to a server pins its key, and the JSON answer
// says so in meta.host_keys_pinned, for an agent to show the person; the
// next connection pins nothing.
func TestPinnedKeyInOutput(t *testing.T) {
	startSessionServer(t, "up 1 day\n", true)
	run := func() []any {
		t.Helper()
		d, e := invRun(t, "--host-key-policy", "accept-new", "host", "ssh", "exec", "dev", "--read-only", "--", "uptime")
		if e != nil {
			t.Fatal(e)
		}
		pinned, _ := d["_meta"].(map[string]any)["host_keys_pinned"].([]any)
		return pinned
	}
	pinned := run()
	if len(pinned) != 1 {
		t.Fatalf("first connection: %v", pinned)
	}
	k := pinned[0].(map[string]any)
	if k["host"] != "dev" || k["key_type"] != "ssh-ed25519" || !strings.HasPrefix(fmt.Sprint(k["fingerprint"]), "SHA256:") || !strings.Contains(fmt.Sprint(k["address"]), "localhost") {
		t.Errorf("pinned key: %v", k)
	}
	if again := run(); len(again) != 0 {
		t.Errorf("second connection: %v", again)
	}
}

// A key pinned on first connect through a leaf that runs a body keeps its
// own record name: host ssh exec does not rename it.
func TestPinnedKeyThroughExecKeepsItsName(t *testing.T) {
	srv := startFakeServer(t)
	srv.reply("up 1 day")
	if _, e := invRun(t, "--host-key-policy", "accept-new", "host", "ssh", "exec", "dev", "--read-only", "--", "uptime"); e != nil {
		t.Fatal(e)
	}
	a := auditText(t)
	if !strings.Contains(a, `"event":"host.key-pinned"`) { // rule R1: the event under the leaf that ran
		t.Errorf("no host.key-pinned record:\n%s", a)
	}
	if !strings.Contains(a, `"command":"host.ssh.exec"`) {
		t.Errorf("no record of the exec itself:\n%s", a)
	}
}

// A password stored by host ssh add --ask-password keeps its secret.set
// record, with the secret's name.
func TestAskPasswordThroughHostAddKeepsSecretSet(t *testing.T) {
	invHome(t)
	saved, savedTerminal := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = saved, savedTerminal })
	tcl.terminal = true
	readPassword = func(*call, string) (string, error) { return "Typed-Pass-9", nil }
	mustRun(t, "host", "ssh", "add", "vps9", "root@10.0.0.29", "--ask-password")
	a := auditText(t)
	for _, want := range []string{`"event":"secret.set"`, `"secret":"vps9-pass"`, `"for":"host vps9"`, `"replaced":false`} {
		if !strings.Contains(a, want) {
			t.Errorf("no %s in:\n%s", want, a)
		}
	}
}
