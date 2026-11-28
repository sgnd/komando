package cli

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/sshx"
)

// Row C625 (2): a record written before rule R1 kept an event's name in
// command and had no event field. The reader gives it its event, so one
// query (and one field) finds the old record and the new one.
func TestAuditOldEventRecordsReadAsEvents(t *testing.T) {
	invHome(t)
	noAgent(t)
	if _, err := writeAudit(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "command": "host.key-pinned", "ok": true, "actor": "v0.17", "hosts": []string{"web1"}}); err != nil {
		t.Fatal(err)
	}
	sshx.HostKeyPinned(withCall(context.Background(), tcl), sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	d := mustRun(t, "audit", "list", "--command", "host.key-pinned", "-n", "0")
	var events, actors []string
	for _, e := range d["entries"].([]any) {
		r := e.(map[string]any)
		ev, _ := r["event"].(string)
		a, _ := r["actor"].(string)
		events, actors = append(events, ev), append(actors, a)
	}
	if !slices.Equal(events, []string{"host.key-pinned", "host.key-pinned"}) || len(actors) != 2 || actors[0] != "v0.17" {
		t.Fatalf("entries: events %v, actors %v", events, actors)
	}
	// a v0.17 command ID in command stays a command
	if _, err := writeAudit(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "command": "vpn.add", "ok": true, "actor": "v0.17"}); err != nil {
		t.Fatal(err)
	}
	d = mustRun(t, "audit", "list", "--command", "vpn.add", "-n", "0")
	for _, e := range d["entries"].([]any) {
		if ev, ok := e.(map[string]any)["event"]; ok {
			t.Errorf("vpn.add read as the event %v", ev)
		}
	}
}
