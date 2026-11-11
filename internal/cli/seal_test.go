package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// asSealPerson runs the rest of the test as a person at a terminal who
// answers yes, on a folder of before.
func asSealPerson(t *testing.T) {
	t.Helper()
	for _, a := range agentVars {
		t.Setenv(a.env, "")
		resetApproval()
		os.Unsetenv(a.env)
		resetApproval()
	}
	savedI, savedC := interactive, sealConfirm
	interactive = func() bool { return true }
	sealConfirm = func(string) bool { return true }
	t.Cleanup(func() {
		interactive, sealConfirm = savedI, savedC
		store.UseSealedForNewHomes(os.Getenv("KOMANDO_TEST_SEALED") == "1")
	})
}

// oldFolderFixture fills a folder of before: servers (one with a key file
// as its identity), a conn, a secret, a key komando made, a pinned host
// key, a recipe, deny rules and an audit log.
func oldFolderFixture(t *testing.T) {
	t.Helper()
	store.UseSealedForNewHomes(false)
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	mustRun(t, "host", "add", "db1", "deploy@10.0.0.2", "--via", "web1")
	mustRun(t, "conn", "add", "pg", "postgres://app@10.0.0.3/app", "--password-ref", "secret:pg-pass")
	setSecret(t, "pg-pass", "pg-s3cret-value")
	mustRun(t, "key", "gen", "deploy")
	mustRun(t, "host", "edit", "web1", "--key", "deploy")
	mustRun(t, "host", "edit", "web1", "--protected")
	mustRun(t, "host", "add", "byfile", "u@10.0.0.4", "--identity", store.Path("keys", "deploy"))
	mustRun(t, "recipe", "add", "up", "uptime", "--read-only")
	mustRun(t, "policy", "deny", "drop table")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	if _, err := sshx.PinHostKey("10.0.0.1:22", k, false); err != nil {
		t.Fatal(err)
	}
	if store.Sealed() {
		t.Fatal("the fixture is not a folder of before")
	}
}

func TestSealAndUndo(t *testing.T) {
	t.Run("passphrase", func(t *testing.T) { sealAndUndo(t, true) })
	t.Run("key file", func(t *testing.T) { sealAndUndo(t, false) })
}

func sealAndUndo(t *testing.T, passphrase bool) {
	invHome(t)
	if !passphrase {
		t.Setenv("KOMANDO_VAULT_PASS", "")
		vault.ReadPassStdin(strings.NewReader("")) // forget one read earlier
	}
	asSealPerson(t)
	oldFolderFixture(t)
	before, _ := store.Load()
	priv, _ := os.ReadFile(store.Path("keys", "deploy"))

	d := mustRun(t, "seal", "--dry-run")
	if d["action"] != "would_seal" || d["hosts"].(float64) != 3 || d["secrets"].(float64) != 1 || d["pinned_host_keys"].(float64) != 1 {
		t.Fatalf("dry run: %v", d)
	}
	if store.Sealed() {
		t.Fatal("the dry run sealed")
	}
	d = mustRun(t, "seal")
	if d["action"] != "sealed" {
		t.Fatalf("seal: %v", d)
	}
	if !store.Sealed() || store.MixedHome() {
		t.Fatalf("sealed %v mixed %v", store.Sealed(), store.MixedHome())
	}
	// everything reads back, from the store
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Hosts["web1"].Protected || st.Hosts["db1"].Via != "web1" || len(st.Settings.ExtraDenyPattern) != len(before.Settings.ExtraDenyPattern) {
		t.Fatal("inventory changed in the move")
	}
	if st.Hosts["byfile"].Identity != "" || st.Hosts["byfile"].Key != "deploy" {
		t.Fatalf("a server given the key file did not follow the key: %+v", st.Hosts["byfile"])
	}
	if !store.SealedKey(st.Keys["deploy"]) {
		t.Fatal("the key is not in the store")
	}
	if b, _ := store.ReadPrivateKey(st.Keys["deploy"]); string(b) != string(priv) {
		t.Fatal("the key changed")
	}
	if v, err := vault.Get("pg-pass"); err != nil || v != "pg-s3cret-value" {
		t.Fatalf("secret %q %v", v, err)
	}
	if pins, _ := sshx.PinnedKeys("10.0.0.1:22"); len(pins) != 1 {
		t.Fatal("pin lost")
	}
	if !strings.Contains(auditText(t), `"command":"host.add"`) {
		t.Fatal("audit log of before lost")
	}
	// the files of before hold only the note; nothing readable is left
	for _, f := range []string{"state.json", "vault.json", "known_hosts", "audit.jsonl", "keys/deploy"} {
		if !store.IsMovedNote(store.Path(f)) {
			t.Errorf("%s is not the note", f)
		}
	}
	if _, err := os.Stat(store.Path("vault.key")); !os.IsNotExist(err) {
		t.Error("vault.key left")
	}
	// an older komando reading the note stops: it is not valid data
	if json.Valid([]byte(store.MovedNote)) {
		t.Error("the note reads as JSON")
	}
	if b, _ := os.ReadFile(store.Path("store.db")); strings.Contains(string(b), "pg-s3cret") || strings.Contains(string(b), "web1") {
		t.Error("store.db holds plain text")
	}
	if d := mustRun(t, "seal"); d["action"] != "already_sealed" {
		t.Fatalf("second seal: %v", d)
	}

	// undo: the files of before come back, as they were
	d = mustRun(t, "seal", "--undo")
	if d["action"] != "undone" {
		t.Fatalf("undo: %v", d)
	}
	if store.Sealed() {
		t.Fatal("still sealed after undo")
	}
	back, err := store.Load()
	if err != nil || !back.Hosts["web1"].Protected || back.Hosts["byfile"].Identity == "" {
		t.Fatalf("undo: %v", err)
	}
	if v, err := vault.Get("pg-pass"); err != nil || v != "pg-s3cret-value" {
		t.Fatalf("secret after undo %q %v", v, err)
	}
	if b, _ := os.ReadFile(store.Path("keys", "deploy")); string(b) != string(priv) {
		t.Fatal("key file not back")
	}
}

func TestSealNeedsAPerson(t *testing.T) {
	invHome(t)
	store.UseSealedForNewHomes(false)
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	t.Setenv("KOMANDO_AGENT", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	if _, e := invRun(t, "seal"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
	if store.Sealed() {
		t.Fatal("an agent sealed the folder")
	}
}

// The review's ways to lose data, each on a folder of before.
func TestSealHardCases(t *testing.T) {
	invHome(t)
	asSealPerson(t)
	oldFolderFixture(t)
	// a key file komando does not list, an IPv6 pin and a revoked line
	stray := store.Path("keys", "stray")
	if err := os.WriteFile(stray, []byte("STRAY-PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k6, _ := ssh.NewPublicKey(pub)
	if _, err := sshx.PinHostKey("[2001:db8::7]:2222", k6, false); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(sshx.KnownHostsPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("@revoked 10.9.9.9 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k6))) + "\n")
	f.Close()

	d := mustRun(t, "seal")
	if d["action"] != "sealed" {
		t.Fatalf("seal: %v", d)
	}
	if b, _ := os.ReadFile(stray); string(b) != "STRAY-PRIVATE" {
		t.Error("a key file the store did not take was replaced")
	}
	if pins, _ := sshx.PinnedKeys("[2001:db8::7]:2222"); len(pins) != 1 {
		t.Error("the IPv6 pin did not come over")
	}
	if pins, _ := sshx.PinnedKeys("10.9.9.9:22"); len(pins) != 0 {
		t.Error("a revoked key became a pin")
	}

	// the store's key changes after the move: the archive still opens
	if _, err := vault.ChangeKey("", "a new passphrase, long enough"); err != nil {
		t.Fatal(err)
	}
	if d := mustRun(t, "seal", "--undo"); d["action"] != "undone" {
		t.Fatalf("undo after a key change: %v", d)
	}
	// and the folder can be sealed again
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	vault.ReadPassStdin(strings.NewReader("test-passphrase-long-enough"))
	if d := mustRun(t, "seal"); d["action"] != "sealed" {
		t.Fatalf("seal again: %v", d)
	}
	// store.db lost after a move: komando stops, it does not start empty
	if err := os.Rename(store.Path("store.db"), store.Path("store.db.gone")); err != nil {
		t.Fatal(err)
	}
	if _, e := invRun(t, "host", "list"); e == nil || e.Code != "STATE_CORRUPT" {
		t.Fatalf("store lost: %+v", e)
	}
}
