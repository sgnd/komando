package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

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
		os.Unsetenv(a.env)
	}
	savedI, savedC := interactive, sealConfirm
	interactive = func() bool { return true }
	sealConfirm = func(string) bool { return true }
	t.Cleanup(func() {
		interactive, sealConfirm = savedI, savedC
	})
}

// oldFolderFixture writes a folder of before as an earlier komando left
// it: state.json with servers (one with a key file as its identity), a
// conn, a key komando made, a recipe and deny rules; vault.json with one
// secret, sealed with the passphrase or a key in vault.key; known_hosts
// with one pin; keys/deploy; and an audit log.
func oldFolderFixture(t *testing.T, passphrase bool) {
	t.Helper()
	if err := os.MkdirAll(store.Path("keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(priv, "komando-deploy")
	signer, _ := ssh.NewSignerFromKey(priv)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " komando-deploy"
	keyPath := store.Path("keys", "deploy")
	writeOld(t, "keys/deploy", pem.EncodeToMemory(block))
	writeOld(t, "keys/deploy.pub", []byte(pubLine+"\n"))
	now := time.Unix(1700000000, 0).UTC()
	st := store.State{
		Hosts: map[string]*store.Host{
			"web1":   {Name: "web1", Address: "10.0.0.1", User: "deploy", Key: "deploy", Protected: true, CreatedAt: now, UpdatedAt: now},
			"db1":    {Name: "db1", Address: "10.0.0.2", User: "deploy", Via: "web1", CreatedAt: now, UpdatedAt: now},
			"byfile": {Name: "byfile", Address: "10.0.0.4", User: "u", Identity: keyPath, CreatedAt: now, UpdatedAt: now},
		},
		Conns: map[string]*store.Conn{"pg": {Name: "pg", Kind: "postgres", URL: "postgres://app@10.0.0.3/app", PasswordRef: "secret:pg-pass", CreatedAt: now, UpdatedAt: now}},
		Keys: map[string]*store.Key{"deploy": {Name: "deploy", Path: keyPath, Type: signer.PublicKey().Type(), PublicKey: pubLine,
			Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Managed: true, CreatedAt: now}},
		Snippets: map[string]*store.Snippet{"up": {Name: "up", Command: "uptime", ReadOnly: true, CreatedAt: now}},
		Settings: store.DefaultSettings(),
	}
	st.Settings.ExtraDenyPattern = []string{"drop table"}
	b, _ := json.MarshalIndent(&st, "", "  ")
	writeOld(t, "state.json", b)
	secret := []byte(vault.Passphrase())
	if !passphrase {
		secret = make([]byte, 32)
		rand.Read(secret)
		writeOld(t, "vault.key", secret)
	}
	writeOld(t, "vault.json", oldVault(t, passphrase, secret, map[string]string{"pg-pass": "pg-s3cret-value"}))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	writeOld(t, "known_hosts", []byte(knownhosts.Line([]string{"10.0.0.1"}, k)+"\n"))
	writeOld(t, "audit.jsonl", []byte(`{"ts":"2023-11-14T22:13:20Z","command":"host.add","ok":true}`+"\n"))
	if !store.NeedsSeal() {
		t.Fatal("the fixture is not a folder of before")
	}
}

func writeOld(t *testing.T, rel string, b []byte) {
	t.Helper()
	if err := os.WriteFile(store.Path(rel), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// oldVault is vault.json as an earlier komando wrote it: each value sealed
// with AES-256-GCM under scrypt(secret, salt), bound to its name.
func oldVault(t *testing.T, passphrase bool, secret []byte, values map[string]string) []byte {
	t.Helper()
	salt := make([]byte, 16)
	rand.Read(salt)
	mode, n := "keyfile", 1<<15 // the cost of a vault that did not store it
	if passphrase {
		mode, n = "passphrase", 1<<10
	}
	key, err := scrypt.Key(secret, salt, n, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(blk)
	type entry struct {
		Nonce     []byte    `json:"nonce"`
		Data      []byte    `json:"data"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	entries := map[string]entry{}
	for name, v := range values {
		nonce := make([]byte, a.NonceSize())
		rand.Read(nonce)
		entries[name] = entry{nonce, a.Seal(nil, nonce, []byte(v), []byte(name)), time.Unix(1700000000, 0).UTC()}
	}
	f := map[string]any{"version": 1, "salt": salt, "mode": mode, "entries": entries}
	if passphrase {
		f["scrypt_n"] = n
	}
	b, _ := json.Marshal(f)
	return b
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
	oldFolderFixture(t, passphrase)
	before, _ := store.ReadOldState()
	priv, _ := os.ReadFile(store.Path("keys", "deploy"))

	d := mustRun(t, "seal", "--dry-run")
	if d["action"] != "would_seal" || d["hosts"].(float64) != 3 || d["secrets"].(float64) != 1 || d["pinned_host_keys"].(float64) != 1 {
		t.Fatalf("dry run: %v", d)
	}
	if !store.NeedsSeal() {
		t.Fatal("the dry run sealed")
	}
	d = mustRun(t, "seal")
	if d["action"] != "sealed" {
		t.Fatalf("seal: %v", d)
	}
	if store.NeedsSeal() || store.MixedHome() {
		t.Fatalf("needs seal %v mixed %v", store.NeedsSeal(), store.MixedHome())
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
	if v := mustRun(t, "audit", "verify"); v["ok"] != true {
		t.Fatalf("audit verify after the move: %v", v)
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
	if !store.NeedsSeal() {
		t.Fatal("still sealed after undo")
	}
	back, err := store.ReadOldState()
	if err != nil || !back.Hosts["web1"].Protected || back.Hosts["byfile"].Identity == "" {
		t.Fatalf("undo: %v", err)
	}
	secrets, err := vault.ExportFiles()
	if err != nil || string(secrets["pg-pass"].Value) != "pg-s3cret-value" {
		t.Fatalf("secret after undo %v", err)
	}
	if b, _ := os.ReadFile(store.Path("keys", "deploy")); string(b) != string(priv) {
		t.Fatal("key file not back")
	}
	wantCode(t, "NEEDS_SEAL", "host", "list")
}

func TestSealNeedsAPerson(t *testing.T) {
	invHome(t)
	oldFolderFixture(t, true)
	t.Setenv("KOMANDO_AGENT", "1")
	if _, e := invRun(t, "seal"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
	if !store.NeedsSeal() {
		t.Fatal("an agent sealed the folder")
	}
}

// The review's ways to lose data, each on a folder of before.
func TestSealHardCases(t *testing.T) {
	invHome(t)
	asSealPerson(t)
	oldFolderFixture(t, true)
	// a key file komando does not list, an IPv6 pin and a revoked line
	stray := store.Path("keys", "stray")
	if err := os.WriteFile(stray, []byte("STRAY-PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k6, _ := ssh.NewPublicKey(pub)
	f, _ := os.OpenFile(store.Path("known_hosts"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(knownhosts.Line([]string{"[2001:db8::7]:2222"}, k6) + "\n")
	f.WriteString("@revoked 10.9.9.9 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k6))) + "\n")
	f.Close()

	f, _ = os.OpenFile(store.Path("known_hosts"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(knownhosts.Line([]string{"*.example.com"}, k6) + "\n")
	f.Close()
	var asked string
	sealConfirm = func(q string) bool { asked = q; return true }
	d := mustRun(t, "seal")
	if d["action"] != "sealed" || d["revoked_host_keys"].(float64) != 1 {
		t.Fatalf("seal: %v", d)
	}
	if !strings.Contains(asked, "*.example.com") || !strings.Contains(asked, "pinned again without asking") {
		t.Errorf("the question does not name the entries it drops: %q", asked)
	}
	if b, _ := os.ReadFile(stray); string(b) != "STRAY-PRIVATE" {
		t.Error("a key file the store did not take was replaced")
	}
	if pins, _ := sshx.PinnedKeys("[2001:db8::7]:2222"); len(pins) != 0 {
		t.Error("a pin whose key is also @revoked came over")
	}
	if pins, _ := sshx.PinnedKeys("10.9.9.9:22"); len(pins) != 0 {
		t.Error("a revoked key became a pin")
	}
	if rev, err := sshx.HostKeyRevoked(k6); !rev || err != nil {
		t.Errorf("the @revoked key was not carried as never-trust: %v", err)
	}
	if _, err := sshx.PinHostKey("10.9.9.9:22", k6, false); err == nil {
		t.Error("a revoked key could be pinned")
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

// A folder of before stops every command but the few that help a person
// move it, for people, scripts and agents alike, and nothing is made in
// it meanwhile.
func TestNeedsSealStopsCommands(t *testing.T) {
	invHome(t)
	oldFolderFixture(t, true)
	for _, agent := range []bool{false, true} {
		if agent {
			t.Setenv("KOMANDO_AGENT", "1")
		}
		for _, args := range [][]string{{"host", "list"}, {"host", "add", "x", "u@10.0.0.9"}, {"secret", "list"}, {"audit"}, {"exec", "web1", "--read-only", "--", "uptime"}} {
			e := wantCode(t, "NEEDS_SEAL", args...)
			if !strings.Contains(e.Hint, "komando seal") || !strings.Contains(e.Hint, "own terminal") {
				t.Errorf("%v: hint %q", args, e.Hint)
			}
		}
		mustRun(t, "version")
		mustRun(t, "schema", "host.add")
		if d := mustRun(t, "seal", "--dry-run"); d["action"] != "would_seal" || d["secrets"].(float64) != 1 {
			t.Fatalf("seal --dry-run: %v", d)
		}
		if _, e := invRun(t, "doctor"); e == nil || e.Code != "NEEDS_SEAL" {
			t.Fatalf("doctor: %+v", e)
		}
	}
	if _, err := os.Stat(store.Path(store.StoreFile)); !os.IsNotExist(err) {
		t.Fatal("a store was made beside the files of before")
	}
}
