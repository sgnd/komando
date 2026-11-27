package cli

import (
	"context"
	"encoding/json"
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
	for _, want := range []string{`"command":"host.key-pinned"`, `"hosts":["web1"]`, `"fingerprint":"SHA256:abc"`, `"key_type":"ssh-ed25519"`, `"first_use":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit record %s has no %s", b, want)
		}
	}
}

// The first connection to a server pins its key, and the JSON answer
// says so in meta.host_keys_pinned, for an agent to show the person; the
// next connection pins nothing.
func TestPinnedKeyInOutput(t *testing.T) {
	srv := startFakeServer(t)
	run := func() []any {
		t.Helper()
		srv.reply("up 1 day")
		d, e := invRun(t, "--host-key-policy", "accept-new", "exec", "dev", "--read-only", "--", "uptime")
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

// A leaf that runs a body (runBody) names the command's own record with its
// ID; a record the call names itself keeps its name: a key pinned on first
// use, a password typed with --ask-password.
func TestNamedAuditRecordsKeepTheirName(t *testing.T) {
	invHome(t)
	saved := tcl.out.As
	tcl.out.As = "queue.kafka.info" // as runBody sets it
	sshx.HostKeyPinned(withCall(context.Background(), tcl), sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	tcl.out.As = saved
	if r := lastAudit(t); r["command"] != "host.key-pinned" || r["fingerprint"] != "SHA256:abc" {
		t.Errorf("a key pinned under a leaf: %v", r)
	}

	noAgent(t)
	savedRead, savedTerminal := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = savedRead, savedTerminal })
	tcl.terminal = true
	readPassword = func(*call, string) (string, error) { return "Typed-Vpn-1", nil }
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080", "--user", "budi", "--ask-password")
	var set, add map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		_ = json.Unmarshal([]byte(line), &r)
		switch r["command"] {
		case "secret.set":
			set = r
		case "vpn.socks.add":
			add = r
		}
	}
	if set == nil || set["secret"] != "lab-pass" || set["for"] != "vpn lab" || set["replaced"] != false {
		t.Errorf("--ask-password under a leaf: secret.set record %v", set)
	}
	if add == nil {
		t.Errorf("the leaf's own record is not named vpn.socks.add:\n%s", auditText(t))
	}
}
