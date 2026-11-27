package cli

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/sshx"
)

// Chief rule R1 (row C604): every audit record names the leaf that ran and
// its safety key; an event adds a name from the closed list (auditEvents).

// wantIdentity fails unless r names the leaf id, the key of id and the
// event ev ("" for the command's own record).
func wantIdentity(t *testing.T, r map[string]any, id, ev string) {
	t.Helper()
	k, _ := r["safety_key"].(map[string]any)
	want, ok := cmdKeys[id]
	if !ok {
		t.Fatalf("%s has no safety key", id)
	}
	if r["command"] != id || k == nil || k["type"] != want.typ || k["area"] != want.area || k["verb"] != want.verb {
		t.Errorf("record %v: want command %s and key %+v", r, id, want)
	}
	if got, _ := r["event"].(string); got != ev {
		t.Errorf("record %v: want event %q", r, ev)
	}
}

// Every name a call gives the audit log is a command ID with a safety key
// (audit) or a member of the closed list (auditEvent, with a literal).
func TestAuditNamesAreIDsOrListedEvents(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) < 3 {
				return true
			}
			fn, ok := c.Fun.(*ast.Ident)
			if !ok || fn.Name != "audit" && fn.Name != "auditEvent" {
				return true
			}
			calls++
			at := fset.Position(c.Pos())
			lit, ok := c.Args[2].(*ast.BasicLit)
			if !ok {
				if fn.Name == "auditEvent" {
					t.Errorf("%s: auditEvent names its event with a literal of auditEvents", at)
				}
				return true
			}
			name, _ := strconv.Unquote(lit.Value)
			switch {
			case fn.Name == "audit" && !hasSafetyKey(name):
				t.Errorf("%s: audit(%q): not a command ID; an event goes through auditEvent", at, name)
			case fn.Name == "auditEvent" && !slices.Contains(auditEvents, name):
				t.Errorf("%s: auditEvent(%q): not in auditEvents", at, name)
			}
			return true
		})
	}
	if calls < 100 {
		t.Fatalf("found %d audit calls: the scan is broken", calls)
	}
}

// A command's own record: today's command and a table leaf.
func TestAuditRecordNamesLeafAndKey(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.5")
	wantIdentity(t, lastAudit(t), "host.add", "")
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080")
	wantIdentity(t, lastAudit(t), "vpn.socks.add", "")
}

// Events keep their names in the event field, under the leaf that ran: a
// host key pinned on first use, a password typed with --ask-password.
func TestAuditEventsUnderTheirLeaf(t *testing.T) {
	invHome(t)
	saved := tcl.out.As
	tcl.out.As = "queue.kafka.info" // as runBody sets it
	sshx.HostKeyPinned(withCall(context.Background(), tcl), sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	tcl.out.As = saved
	r := lastAudit(t)
	wantIdentity(t, r, "queue.kafka.info", "host.key-pinned")
	if r["fingerprint"] != "SHA256:abc" {
		t.Errorf("pinned key record: %v", r)
	}

	noAgent(t)
	savedRead, savedTerminal := readPassword, tcl.terminal
	t.Cleanup(func() { readPassword, tcl.terminal = savedRead, savedTerminal })
	tcl.terminal = true
	readPassword = func(*call, string) (string, error) { return "Typed-Vpn-1", nil }
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080", "--user", "budi", "--ask-password")
	var stored map[string]any
	for _, r := range auditRecords(t) {
		if r["event"] == "secret.set" {
			stored = r
		}
	}
	if stored == nil || stored["secret"] != "lab-pass" {
		t.Fatalf("no secret.set event: %s", auditText(t))
	}
	wantIdentity(t, stored, "vpn.socks.add", "secret.set")
}

// `audit --command` matches by safety key: an ID of v0.17 and the leaf's
// ID both find an old record (never rewritten) and a new one; an event
// name finds its events.
func TestAuditCommandReadsOldAndNewRecords(t *testing.T) {
	invHome(t)
	noAgent(t)
	old := capability.TodayKeys()["vpn.add"]
	if k := cmdKeys["vpn.socks.add"]; old.Type != k.typ || old.Area != k.area || old.Verb != k.verb {
		t.Fatalf("vpn.add %+v and vpn.socks.add %+v do not share a key", old, k)
	}
	if _, err := writeAudit(map[string]any{"ts": time.Now().UTC().Format(time.RFC3339Nano), "command": "vpn.add", "ok": true, "actor": "v0.17"}); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "vpn", "socks", "add", "lab", "--proxy-address", "127.0.0.1:1080")
	saved := tcl.out.As
	tcl.out.As = "queue.kafka.info" // a key pinned while another leaf dials
	sshx.HostKeyPinned(withCall(context.Background(), tcl), sshx.NewHostKey{Host: "web1", Address: "203.0.113.10:22", Type: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	tcl.out.As = saved
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"vpn.add", []string{"vpn.add", "vpn.socks.add"}},
		{"vpn.socks.add", []string{"vpn.add", "vpn.socks.add"}},
		{"vpn socks add", []string{"vpn.add", "vpn.socks.add"}},
		{"host.key-pinned", []string{"host.key-pinned"}},
	} {
		d := mustRun(t, "audit", "--command", tc.filter, "-n", "0")
		var got []string
		for _, e := range d["entries"].([]any) {
			r := e.(map[string]any)
			if ev, _ := r["event"].(string); ev != "" {
				got = append(got, ev)
				continue
			}
			got = append(got, r["command"].(string))
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("audit --command %q: %v, want %v", tc.filter, got, tc.want)
		}
	}
}

func hasSafetyKey(id string) bool { _, ok := auditKeyOf(id); return ok }

// auditRecords are the records of the audit log, oldest first.
func auditRecords(t *testing.T) []map[string]any {
	t.Helper()
	var rs []map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		if json.Unmarshal([]byte(line), &r) == nil && r != nil {
			rs = append(rs, r)
		}
	}
	return rs
}
