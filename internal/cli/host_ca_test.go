package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func caPub(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	p := filepath.Join(t.TempDir(), "ca.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(k), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, k
}

// Adding a CA needs a person at a terminal; an agent's and a script's
// dry run shows what would be kept and which servers it would match.
func TestHostCAAddNeedsAPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "--address", "web1.corp.example", "--user", "u")
	mustRun(t, "host", "ssh", "add", "db1", "--address", "db1.other.example", "--user", "u")
	p, k := caPub(t)
	d := mustRun(t, "credential", "certificate", "add", "corp", "--key", p, "--hosts", "*.Corp.example", "--dry-run")
	items := d["items"].([]any)
	row := items[0].(map[string]any)
	if d["action"] != "would_add" || row["fingerprint"] != ssh.FingerprintSHA256(k) || row["hosts"].([]any)[0] != "*.corp.example" || len(row["would_match"].([]any)) != 1 || row["would_match"].([]any)[0] != "web1" {
		t.Fatalf("dry run: %v", d)
	}
	_, e := invRun(t, "credential", "certificate", "add", "corp", "--key", p, "--hosts", "*.corp.example")
	if e == nil || e.Code != "NEEDS_PERSON" || e.Exit != out.ExitPolicy {
		t.Fatalf("a script added a CA: %+v", e)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	_, e = invRun(t, "credential", "certificate", "add", "corp", "--key", p, "--hosts", "*.corp.example")
	if e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("an agent added a CA: %+v", e)
	}
	if cas, _ := sshx.HostCAs(t.Context()); len(cas) != 0 {
		t.Fatalf("a CA was added: %v", cas)
	}
}

// Patterns that vouch for too much are refused, in the dry run too.
func TestHostCAAddRefusesWidePatterns(t *testing.T) {
	invHome(t)
	p, _ := caPub(t)
	for _, h := range []string{"*", "*.com", "*.*", "!x.corp.example"} {
		_, e := invRun(t, "credential", "certificate", "add", "corp", "--key", p, "--hosts", h, "--dry-run")
		if e == nil || (e.Code != "CA_HOSTS_INVALID" && e.Code != "USAGE") {
			t.Errorf("%q: %+v", h, e)
		}
	}
	if _, e := invRun(t, "credential", "certificate", "add", "corp", "--key", p, "--dry-run"); e == nil || e.Code != "CA_HOSTS_INVALID" {
		t.Errorf("no --hosts: %+v", e)
	}
}

// A person adds a CA (from a known_hosts file, whose @revoked lines go on
// the never-trust list); anyone lists, removes and revokes.
func TestHostCAPersonAddsAndAnyoneRemoves(t *testing.T) {
	invHome(t)
	_, k := caPub(t)
	_, old := caPub(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	body := "web1 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(old))) + "\n" +
		"@cert-authority *.corp.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " corp-ca\n" +
		"@revoked * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(old))) + "\n"
	if err := os.WriteFile(kh, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	asPerson(t, func(string) string { return "" }, func() {
		d := mustRun(t, "credential", "certificate", "add", "corp", "--from", kh)
		if d["action"] != "added" || d["revoked"] != float64(1) {
			t.Errorf("add: %v", d)
		}
	})
	if rev, _ := sshx.HostKeyRevoked(old); !rev {
		t.Error("the @revoked line was not read")
	}
	l := mustRun(t, "credential", "certificate", "list")["items"].([]any)
	if len(l) != 1 || l[0].(map[string]any)["name"] != "corp" || l[0].(map[string]any)["fingerprint"] != ssh.FingerprintSHA256(k) {
		t.Fatalf("list: %v", l)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	if d := mustRun(t, "credential", "certificate", "remove", "corp"); d["action"] != "removed" {
		t.Errorf("rm: %v", d)
	}
	if _, e := invRun(t, "credential", "certificate", "remove", "corp"); e == nil || e.Code != "CA_NOT_FOUND" {
		t.Errorf("rm twice: %+v", e)
	}
	p, k2 := caPub(t)
	if d := mustRun(t, "host", "ca", "revoke", "--key", p); d["action"] != "revoked" {
		t.Errorf("revoke: %v", d)
	}
	if rev, _ := sshx.HostKeyRevoked(k2); !rev {
		t.Error("not revoked")
	}
}

// host show names the CA that vouches for a server; doctor warns about a
// CA that vouches for a protected server.
func TestHostCAShowAndDoctor(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "--address", "web1.corp.example", "--user", "u")
	_, k := caPub(t)
	if err := sshx.AddHostCA(t.Context(), sshx.HostCA{Name: "corp", Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), Hosts: []string{"*.corp.example"}}); err != nil {
		t.Fatal(err)
	}
	if d := mustRun(t, "host", "ssh", "show", "web1"); d["host_ca"] != "corp" {
		t.Errorf("show: %v", d["host_ca"])
	}
	mustRun(t, "host", "ssh", "edit", "web1", "--protected")
	d, _ := invRun(t, "doctor")
	found := false
	for _, c := range d["security"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "security:host_ca:corp" {
			found = m["warning"] == true && strings.Contains(m["detail"].(string), "web1")
		}
	}
	if !found {
		t.Errorf("doctor: %v", d["security"])
	}
}

// doctor never shows the CAs as healthy when it cannot read them or their
// revoke list (a tampered store): it warns instead.
func TestHostCAChecksReportErrors(t *testing.T) {
	ca := sshx.HostCA{Name: "corp", Key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", Hosts: []string{"*.corp.example"}, AddedAt: time.Now()}
	for _, tc := range []struct {
		name    string
		list    func(context.Context) ([]sshx.HostCA, error)
		revoked func(ssh.PublicKey) (bool, error)
	}{
		{name: "CA list unreadable", list: func(context.Context) ([]sshx.HostCA, error) { return nil, errors.New("tampered") }},
		{name: "revoke list unreadable",
			list:    func(context.Context) ([]sshx.HostCA, error) { return []sshx.HostCA{ca}, nil },
			revoked: func(ssh.PublicKey) (bool, error) { return false, errors.New("tampered") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldL, oldR := hostCAList, hostKeyRevoked
			t.Cleanup(func() { hostCAList, hostKeyRevoked = oldL, oldR })
			hostCAList = tc.list
			if tc.revoked != nil {
				hostKeyRevoked = tc.revoked
			}
			var warned []string
			hostCAChecks(nil, &store.State{}, func(name string, ok, warn bool, detail string, _ ...string) {
				if ok {
					t.Errorf("%s shown healthy: %s", name, detail)
				}
				if warn {
					warned = append(warned, detail)
				}
			})
			if len(warned) == 0 {
				t.Fatal("no warning")
			}
		})
	}
}

// A dry run records the stop the real run hits: an AI agent's preview of
// host ca add says NEEDS_PERSON in would_be_blocked, and still shows what
// it would add.
func TestHostCAAddDryRunRecordsTheStop(t *testing.T) {
	invHome(t)
	p, _ := caPub(t)
	setCallerEnv(t, "CLAUDECODE", "1")
	d, e := invRun(t, "credential", "certificate", "add", "corp", "--key", p, "--hosts", "*.corp.example", "--dry-run")
	setGate(tcl, false, gateDryRun)
	if e != nil || d["action"] != "would_add" || blockedCode(d) != "NEEDS_PERSON" {
		t.Fatalf("dry run: %v %+v", d, e)
	}
}
