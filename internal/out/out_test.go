package out

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRedactHidesVaultSecrets(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Format: "json", W: &buf, Secrets: func() map[string]string {
		return map[string]string{"db-pass": `s3cr"et!x`, "short": "abc", "api": "tok-123456"}
	}}
	p.Print("fs.cat", map[string]any{"content": "DB_PASSWORD=s3cr\"et!x\nAPI=tok-123456\nNAME=abc\n"}, nil)
	got := buf.String()
	if strings.Contains(got, "s3cr") || strings.Contains(got, "tok-123456") {
		t.Fatalf("secret leaked: %s", got)
	}
	if !strings.Contains(got, "DB_PASSWORD=[secret:db-pass]") || !strings.Contains(got, "API=[secret:api]") {
		t.Errorf("secrets not replaced by their names: %s", got)
	}
	if !strings.Contains(got, "NAME=abc") {
		t.Errorf("values shorter than %d must stay: %s", minSecret, got)
	}
	if p.Redact("x tok-123456 y") != "x [secret:api] y" {
		t.Error("text redaction")
	}
	p.NoRedact = true
	if p.Redact("tok-123456") != "tok-123456" {
		t.Error("NoRedact (secret get --reveal) must print the value")
	}
}

func TestTextHeadline(t *testing.T) {
	for _, c := range []struct {
		data map[string]any
		want []string
		not  []string
	}{
		{map[string]any{"name": "web2", "action": "added", "address": "10.0.0.1", "created_at": "2026-11-07T15:26:25Z"},
			[]string{"added web2\n", "  address: 10.0.0.1"}, []string{"action:", "created_at"}},
		{map[string]any{"name": "web2", "action": "would_add"}, []string{"would add web2 (dry run)"}, nil},
		{map[string]any{"name": "web2", "changed": false}, []string{"web2: nothing to change"}, []string{"changed:"}},
		{map[string]any{"name": "web2", "port": 22}, []string{"name: web2\nport: 22"}, nil}, // no change: a plain record, name first
	} {
		got := renderText(c.data, false)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%v: missing %q in\n%s", c.data, w, got)
			}
		}
		for _, n := range c.not {
			if strings.Contains(got, n) {
				t.Errorf("%v: has %q in\n%s", c.data, n, got)
			}
		}
	}
	if got := renderText(map[string]any{"name": "x", "created_at": "2026-11-07T15:26:25Z"}, false); strings.Contains(got, "T15:26:25Z") {
		t.Errorf("times for people are local, not raw RFC3339: %s", got)
	}
}

// Host keys trusted on first use are in meta.host_keys_pinned, and only
// for the command that pinned them.
func TestHostKeysPinnedMeta(t *testing.T) {
	var b bytes.Buffer
	p := &Printer{Format: "json", W: &b, Start: time.Now()}
	p.HostKeyPinned(HostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	p.Print("exec", map[string]any{}, nil)
	if !strings.Contains(b.String(), `"host_keys_pinned":[{"host":"web1","address":"203.0.113.10:22","key_type":"ssh-ed25519","fingerprint":"SHA256:abc"}]`) {
		t.Errorf("meta: %s", b.String())
	}
	p.Reset()
	b.Reset()
	p.Print("exec", map[string]any{}, nil)
	if strings.Contains(b.String(), "host_keys_pinned") {
		t.Errorf("after Reset: %s", b.String())
	}
}

// A preview never says it changed something.
func TestHeadlineDryRun(t *testing.T) {
	m := func() map[string]any { return map[string]any{"name": "web2", "changed": true, "user": "zz"} }
	if got := renderText(m(), false); !strings.HasPrefix(got, "changed web2\n") {
		t.Errorf("real run: %q", got)
	}
	if got := renderText(m(), true); !strings.HasPrefix(got, "would change web2 (dry run)\n") {
		t.Errorf("dry run: %q", got)
	}
}
