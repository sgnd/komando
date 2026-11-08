package cli

import (
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
