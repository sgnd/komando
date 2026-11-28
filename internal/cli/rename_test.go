package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// homeFiles is the store and runtime.json, to check that nothing changed.
func homeFiles(t *testing.T) string {
	t.Helper()
	db, _ := os.ReadFile(store.Path(store.StoreFile))
	rt, _ := os.ReadFile(store.Path("runtime.json"))
	return string(db) + "\n--runtime--\n" + string(rt)
}

// An AI agent renames entries that no protected server or conn depends on
// without a person's yes: the same values go to the same places, so no
// window opens (TestMain fails a test that opens one).
func TestRenameAgentNeedsNoWindow(t *testing.T) {
	invHome(t)
	if err := vault.Set(store.Save(), "lab-pass", "v"); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "vpn", "socks", "add", "lab-vpn", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "host", "ssh", "add", "lab-a", "u@10.0.0.1", "--via", "lab-vpn", "--credential", "lab-pass", "--env", "P=credential:lab-pass")
	mustRun(t, "conn", "add", "lab-db", "postgres://u@10.0.0.2/x", "--via", "lab-vpn,lab-a", "--password-ref", "credential:lab-pass")
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, a := range [][]string{
		{"vpn", "socks", "rename", "lab-vpn", "test-vpn"},
		{"host", "ssh", "rename", "lab-a", "test-a"},
		{"conn", "rename", "lab-db", "test-db"},
		{"credential", "password", "rename", "lab-pass", "test-pass"},
	} {
		if d := mustRun(t, a...); d["to"] != a[len(a)-1] {
			t.Errorf("%v: %v", a, d)
		}
	}
	// a protected entry still needs a person: no screen, so it is refused
	mustRun(t, "host", "ssh", "add", "lab-p", "u@10.0.0.3", "--protected")
	saved := askOnScreen
	askOnScreen = func(*call, string) (bool, bool) { return false, false } // no screen
	t.Cleanup(func() { askOnScreen = saved })
	keep := homeFiles(t)
	wantCode(t, "PROTECTED_TARGET", "host", "ssh", "rename", "lab-p", "test-p", "--yes")
	if homeFiles(t) != keep {
		t.Fatal("a refused rename changed something")
	}
}

// The approval code's secret is never renamed or written over: the vault
// refuses its name whatever the caller asks.
func TestVaultRefusesTheApprovalSecretName(t *testing.T) {
	invHome(t)
	for _, n := range []string{approvalSecret, "komando-other"} {
		if err := vault.Set(store.Save(), n, "v"); err != nil {
			t.Fatal(err)
		}
	}
	if err := vault.RenameMany(store.Save(), map[string]string{"komando-other": approvalSecret}); err == nil {
		t.Error("the vault put a value under the approval code's name")
	}
	if err := vault.RenameMany(store.Save(), map[string]string{approvalSecret: "x"}); err == nil {
		t.Error("the vault moved the approval code's secret")
	}
	if _, err := vault.Get(approvalSecret); err != nil {
		t.Errorf("the approval code's secret moved: %v", err)
	}
}

func TestKeyMv(t *testing.T) {
	invHome(t)
	mustRun(t, "credential", "key", "create", "deploy")
	mustRun(t, "host", "ssh", "add", "web", "u@10.0.0.1", "--key", "deploy")
	mustRun(t, "host", "ssh", "add", "db", "u@10.0.0.2", "--key", "deploy", "--protected")

	keep := homeFiles(t)
	d := mustRun(t, "credential", "key", "rename", "deploy", "deploy-2026", "--dry-run")
	if moved, _ := d["moved"].([]any); d["action"] != "would_rename" || len(moved) != 0 || len(d["updated"].([]any)) != 2 {
		t.Errorf("dry run: %v", d)
	}
	if homeFiles(t) != keep {
		t.Fatal("a dry run changed something")
	}

	d = mustRun(t, "credential", "key", "rename", "deploy", "deploy-2026") // the protected db keeps the same key: no --yes
	if d["action"] != "renamed" {
		t.Fatalf("key mv: %v", d)
	}
	st, _ := store.Load()
	k := st.Keys["deploy-2026"]
	if st.Keys["deploy"] != nil || k == nil || k.Name != "deploy-2026" || !store.SealedKey(k) || k.PublicKey == "" {
		t.Fatalf("key: %+v", k)
	}
	if st.Hosts["web"].Key != "deploy-2026" || st.Hosts["db"].Key != "deploy-2026" {
		t.Errorf("hosts follow: %+v %+v", st.Hosts["web"], st.Hosts["db"])
	}

	// a key added from elsewhere keeps its file where it is
	ext := filepath.Join(t.TempDir(), "id_ext")
	b, _ := store.ReadPrivateKey(k)
	if err := os.WriteFile(ext, b, 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "credential", "key", "add", "ext", ext)
	mustRun(t, "credential", "key", "rename", "ext", "external")
	st, _ = store.Load()
	if st.Keys["external"].Path != ext {
		t.Errorf("an added key's file moved: %+v", st.Keys["external"])
	}
	if _, err := os.Stat(ext); err != nil {
		t.Errorf("the added key's file is gone: %v", err)
	}

	wantCode(t, "SSH_KEY_NOT_FOUND", "credential", "key", "rename", "nosuch", "x")
	wantCode(t, "KEY_EXISTS", "credential", "key", "rename", "external", "deploy-2026")
	wantCode(t, "USAGE", "credential", "key", "rename", "external", "bad name")
	if d := mustRun(t, "credential", "key", "rename", "external", "external"); d["action"] != "unchanged" {
		t.Errorf("same name: %v", d)
	}
}

func TestGroupMv(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "a", "u@10.0.0.1", "-g", "web")
	mustRun(t, "host", "ssh", "add", "b", "u@10.0.0.2", "-g", "Web", "--protected")
	mustRun(t, "conn", "add", "c", "postgres://a@10.0.0.3/x", "-g", "web", "-g", "db")
	mustRun(t, "vpn", "socks", "add", "v", "--proxy-address", "127.0.0.1:1080", "--group", "web")

	// a protected member: one yes
	wantCode(t, "PROTECTED_TARGET", "group", "mv", "web", "frontend")
	d := mustRun(t, "group", "mv", "@web", "frontend", "--dry-run")
	if d["action"] != "would_rename" || len(d["updated"].([]any)) != 4 || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run: %v", d)
	}
	texts := windowText(t, true)
	mustRun(t, "group", "mv", "web", "frontend", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "1 protected server") {
		t.Errorf("one window: %q", *texts)
	}
	st, _ := store.Load()
	if strings.Join(st.Hosts["a"].Groups, ",") != "frontend" || strings.Join(st.Hosts["b"].Groups, ",") != "frontend" ||
		strings.Join(st.Conns["c"].Groups, ",") != "db,frontend" || strings.Join(st.Vpns["v"].Groups, ",") != "frontend" {
		t.Errorf("members: %v %v %v %v", st.Hosts["a"].Groups, st.Hosts["b"].Groups, st.Conns["c"].Groups, st.Vpns["v"].Groups)
	}
	noAgent(t)
	wantCode(t, "GROUP_NOT_FOUND", "group", "mv", "web", "x")
	wantCode(t, "GROUP_EXISTS", "group", "mv", "db", "FRONTEND")
	wantCode(t, "USAGE", "group", "mv", "db", "a b")
	// no protected member: no yes needed
	if d := mustRun(t, "group", "mv", "db", "databases"); d["action"] != "renamed" {
		t.Errorf("group mv: %v", d)
	}
}

// A failure after the vault changed (a VPN folder that cannot move) puts
// the secrets back and leaves the store unchanged.
func TestRenameRollback(t *testing.T) {
	unixOnly(t, "a folder made read-only with chmod (Windows folders ignore it)")
	invHome(t)
	if err := vault.Set(store.Save(), "shop-ts-psk", "value"); err != nil {
		t.Fatal(err)
	}
	secretsNow := func() string {
		var b strings.Builder
		for _, n := range secretNames() {
			v, err := vault.Get(n)
			b.WriteString(n + "=" + v + ";")
			if err != nil {
				t.Fatal(err)
			}
		}
		return b.String()
	}
	if err := store.Update(store.Save(), func(s *store.State) error {
		s.Vpns["shop-ts"] = &store.Vpn{Name: "shop-ts", Kind: "tailscale", PSKRef: "credential:shop-ts-psk"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	vpnDir := store.Path("vpn")
	if err := os.MkdirAll(filepath.Join(vpnDir, "shop-ts-tailscale"), 0o700); err != nil {
		t.Fatal(err)
	}
	s0, h0 := secretsNow(), homeFiles(t)
	if err := os.Chmod(vpnDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vpnDir, 0o700) })
	wantCode(t, "RENAME_FAILED", "vpn", "tailscale", "rename", "shop-ts", "acme-ts")
	_ = os.Chmod(vpnDir, 0o700)
	if secretsNow() != s0 || homeFiles(t) != h0 {
		t.Fatal("a failed folder move left changes")
	}
}
