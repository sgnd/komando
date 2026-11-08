package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// A key pinned on first use is in the audit log with its fingerprint.
func TestPinnedKeyIsAudited(t *testing.T) {
	invHome(t)
	sshx.HostKeyPinned(sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	b, err := os.ReadFile(store.Path("audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
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
